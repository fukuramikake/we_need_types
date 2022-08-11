# ToDo:これはTwitter OAuth 2.0 のテスト

Add-Type -AssemblyName "System.Net.Http"
Add-Type -AssemblyName "System.Web"
Add-Type -AssemblyName "System.Security"
Add-Type -AssemblyName "System.Text.Json"
Add-Type -AssemblyName "System.Linq"
Add-Type -AssemblyName "System.Net.Http.Json"
Add-Type -AssemblyName "System.Collections"

class Settings {
    <# Enter your developer setting #>
    [string]$clientId = ""
    [string]$clientSecret = ""

    Settings() {
        <# Override api key from environment variables #>
        if ($null -ne $env:TWITTER_CLIENT_ID) {
            $this.clientID = $env:TWITTER_CLIENT_ID
        }
        if ($null -ne $env:TWITTER_CLIENT_SECRET) {
            $this.clientSecret = $env:TWITTER_CLIENT_SECRET
        }
    }

    [string]$redirectUri = "http://localhost:8026/" # must be equal to "Callback URI / Redirect URL"
    # [string]$scope = "tweet.read%20tweet.write%20tweet.moderate.write%20users.read%20follows.read%20follows.write%20offline.access%20space.read%20mute.read%20mute.write%20like.read%20like.write%20list.read%20list.write%20block.read%20block.write"
    [string]$scope = "tweet.read%20users.read%20tweet.write%20offline.access"
}

class Init {

    static [AccessTokenResponse] Login([Request]$request, [Settings]$settings) {

        [string]$codeVerifier = [Helper]::GetCodeVerifier()
        [string]$state = [Guid]::NewGuid().ToString()
        [string]$authorizationRequestUrl = [Endpoint]::authorizeUrl + "?response_type=code&client_id=" + $settings.clientId + 
        "&redirect_uri=" + $settings.redirectUri + "&scope=" + $settings.scope + "&state=" + $state + 
        "&code_challenge=" + [Helper]::GetSHA256Challenge($codeVerifier) + "&code_challenge_method=s256"

        try {
            Start-Process $authorizationRequestUrl -PassThru
        }
        finally {
            Write-Host "Open URL:" + $authorizationRequestUrl
        }

        [string]$authorizationCode = $null

        $httpListener = [System.Net.HttpListener]::new() 
        $httpListener.Prefixes.Add($settings.redirectUri)

        [bool]$getAuthorizationCodeResult = $false
        [string]$message = ""
        [System.Net.HttpListenerContext]$context = $null

        try {
            $httpListener.Start()
            while ($httpListener.IsListening) {
                $contextTask = $httpListener.GetContextAsync()

                while (-not $contextTask.AsyncWaitHandle.WaitOne(200)) { }
                $context = $contextTask.GetAwaiter().GetResult()

                if ($context.Request.HttpMethod -eq 'GET' -and $context.Request.RawUrl -ne '/favicon.ico') {
                    $redirectedUri = [System.Uri]::new($context.Request.Url)
                    $query = $redirectedUri.Query
                    $collection = [System.Web.HttpUtility]::ParseQueryString($query)
                    if ($collection.AllKeys.Contains("code") -eq $true -and $collection.AllKeys.Contains("state") -eq $true) {
                    
                        $authorizationCode = $collection.Get("code")
                        if ($collection.Get("state") -eq $state) {
                            $getAuthorizationCodeResult = $true
                            $message = "OK!"
                        }
                        else {
                            $message = "Invalid csrf state!"
                        }
                    }
                    else {
                        $message = "OAuth args not found!"
                    }


                    Write-Host $message
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                    $context.Response.ContentType = "text/plain"
                    $context.Response.ContentLength64 = $buffer.Length
                    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                    $context.Response.OutputStream.Close()

                    if ($getAuthorizationCodeResult -eq $true) {
                        break
                    }

                }
            }
        }
        finally {
            $httpListener.Stop()
        }

        if ($getAuthorizationCodeResult -eq $true) {
            $res = $request.AccessTokenRequest($authorizationCode, $codeVerifier,
                $settings.clientId, $settings.clientSecret, $settings.redirectUri)
            [AccessTokenResponse]$obj = [System.Text.Json.JsonSerializer]::Deserialize($res, [AccessTokenResponse])
            $res = $request.RefreshTokenRequest($obj.refresh_token, $settings.clientId)
            [AccessTokenResponse]$obj = [System.Text.Json.JsonSerializer]::Deserialize($res, [AccessTokenResponse])
            return $obj
        }
        else {
            Write-Host "Get Authorization Code failure."
            return $null
        }
    }
}


class Request {

    [System.Net.Http.HttpClient]$Client

    Request(
        [System.Net.Http.HttpClient]$client
    ) {
        $this.Client = $client
    }

    [System.Net.Http.StringContent] CreateFormUrlEncodedStringContent(
        [Hashtable] $contents
    ) {
        [string]$body = "";
        foreach ($key in $contents.keys) {
            $body += [Helper]::UrlEncode($key) + "=" + [Helper]::UrlEncode($contents[$key]) + "&"
        }
        if ($body -ne "") {
            $body = $body.Substring(0, $body.Length - 1)
        }
        return New-Object -TypeName System.Net.Http.StringContent($body, 
            [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded") 
    }

    [string] AccessTokenRequest(
        [string]$code,
        [string]$verifier,
        [string]$clientId,
        [string]$clientSecret,
        [string]$redirectUri
    ) {
        $header = "Basic " + [System.Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($clientId + ":" + $clientSecret)
        )
        $this.Client.DefaultRequestHeaders.Authorization = $header

        $contents = @{
            "code"          = $code;
            "grant_type"    = "authorization_code";
            "client_id"     = $clientId;
            "redirect_uri"  = $redirectUri;
            "code_verifier" = $verifier
        }

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.PostAsync([Endpoint]::oauth2TokenUrl, $this.CreateFormUrlEncodedStringContent($contents))
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        return $response.Content.ReadAsStringAsync().Result
    }

    [string] RefreshTokenRequest(
        [string]$refreshToken,
        [string]$clientId
    ) {
        $contents = @{
            "refresh_token" = $refreshToken;
            "grant_type"    = "refresh_token";
            "client_id"     = $clientId;
        }

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.PostAsync([Endpoint]::oauth2TokenUrl, $this.CreateFormUrlEncodedStringContent($contents))
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        return $response.Content.ReadAsStringAsync().Result
    }
}


[System.Net.Http.HttpClient]$httpListenerClient = New-Object -TypeName System.Net.Http.HttpClient
[Settings]$settings = [Settings]::new()


$request = [Request]::new($httpListenerClient)

[AccessTokenResponse]$token = $null

try {
    $Error.Clear()
    $token = [Init]::Login($request, $settings)
    Write-Host "Login OK"
    Write-Host "token_type:" $token.token_type
    Write-Host "expires_in:" $token.expires_in
    Write-Host "access_token:" $token.access_token
    Write-Host "scope:" $token.scope
    Write-Host "refresh_token:" $token.refresh_token
    # https://developer.twitter.com/ja/docs/authentication/oauth-2-0
}
catch [Exception] {
    Write-Host $Error
}



class AccessTokenResponse {
    [string]$token_type
    [Int32]$expires_in
    [string]$access_token
    [string]$scope
    [string]$refresh_token
    [string]$error
    [string]$error_description
}

class Helper {

    static [string] GetCodeVerifier() {
        $buffer = [System.Byte[]]::new(32)
        $rand = [System.Random]::new()
        $rand.NextBytes($buffer)
        return [System.Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    }

    static [string] GetSHA256Challenge([string]$codeVerifier) {
        $sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $hash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($codeVerifier))
        return [System.Convert]::ToBase64String($hash).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    }

    static [string] Base64UrlEncode([byte[]]$source) {
        return [System.Convert]::ToBase64String($source).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    }

    static [string] UrlEncode([string]$str) {
        $unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
        [string]$encoded = ""
        foreach ($byte in $bytes) {
            if ($unreserved.IndexOf([char]$byte) -ne -1) {
                $encoded += [char]$byte
            }
            else {
                $encoded += [System.String]::Format("%{0:X2}", $byte)
            }
        }
        return $encoded
    }

}

class Endpoint {
    static [string]$authorizeUrl = "https://twitter.com/i/oauth2/authorize"
    static [string]$oauth2TokenUrl = "https://api.twitter.com/2/oauth2/token"

    static [string]$requestTokenUrl = "https://api.twitter.com/oauth/request_token"
    #static [string]$authorizeUrl = "https://api.twitter.com/oauth/authorize"
    static [string]$accessTokenUrl = "https://api.twitter.com/oauth/access_token"
    static [string]$homeTimeline = "https://api.twitter.com/1.1/statuses/home_timeline.json"
    static [string]$tweets = "https://api.twitter.com/2/tweets"
    static [string]$byUsername = "https://api.twitter.com/2/users/by/username"
    static [string]$users = "https://api.twitter.com/2/users"
}

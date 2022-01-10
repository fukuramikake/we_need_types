Add-Type -AssemblyName "System.Net.Http"
Add-Type -AssemblyName "System.Web"
Add-Type -AssemblyName "System.Security"
Add-Type -AssemblyName "System.Text.Json"
Add-Type -AssemblyName "System.Linq"
Add-Type -AssemblyName "System.Net.Http.Json"
Add-Type -AssemblyName "System.Collections"

class Settings {
    <# Enter your developer setting #>
    [string]$apiKey = ""
    [string]$apiSecret = ""

    Settings() {
        <# Override api key from environment variables #>
        if ($null -ne $env:TWITTER_API_KEY) {
            $this.apiKey = $env:TWITTER_API_KEY
        }
        if ($null -ne $env:TWITTER_API_SECRET) {
            $this.apiSecret = $env:TWITTER_API_SECRET
        }
    }
}

function Login([Request]$request) {

    <# Get Request Token #>
    $request.OauthTokenSecret = ""
    $result = $request.PostRequest($request.RequestTokenUrl, @{
            "oauth_consumer_key"     = $request.ApiKey;
            "oauth_nonce"            = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_timestamp"        = [Helper]::GetTimeStamp();
            "oauth_version"          = "1.0"
        }, @{})

    #[System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
    $result = $result["body"]

    if ( ($null -ne $result) -and ($result -ne "") ) {
        $oauth_token = [System.Text.RegularExpressions.Regex]::Match($result, "oauth_token=(?<str>[0-9a-zA-Z_\\-]+)").Groups["str"].Value
        $oauth_token_secret = [System.Text.RegularExpressions.Regex]::Match($result, "oauth_token_secret=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value
        $oauth_callback_confirmed = [System.Text.RegularExpressions.Regex]::Match($result, "oauth_callback_confirmed=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value
        if ($oauth_token -eq "") {
            Write-Host "request token fail."
            return
        }
        <# Input pin #>
        $url = $request.AuthorizeUrl + "?oauth_token=" + $oauth_token
        
        try {
            $Error.Clear()
            Write-Host "Open url:" + $url
            Start-Process $url
        }
        catch [Exception] {
            Write-Host $Error
        }

        $pin = Read-Host "Input pin code."
        #$ie.Quit()
        $request.OauthTokenSecret = $oauth_token_secret
        <# Get Access Token #>
        $result = $request.PostRequest($request.AccessTokenUrl, @{
                "oauth_consumer_key"     = $request.ApiKey;
                "oauth_nonce"            = [System.Guid]::NewGuid().ToString();
                "oauth_signature_method" = "HMAC-SHA1";
                "oauth_token"            = $oauth_token;
                "oauth_verifier"         = $pin;
                "oauth_timestamp"        = [Helper]::GetTimeStamp();
                "oauth_version"          = "1.0"
            }, @{})

        #[System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
        $result = $result["body"]
        
        if ( ($null -ne $result) -and ($result -ne "") ) {
            $authinfo = @{
                "oauth_token"        = [System.Text.RegularExpressions.Regex]::Match($result, "oauth_token=(?<str>[0-9a-zA-Z_\\-]+)").Groups["str"].Value;
                "oauth_token_secret" = [System.Text.RegularExpressions.Regex]::Match($result, "oauth_token_secret=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value;
                "user_id"            = [System.Text.RegularExpressions.Regex]::Match($result, "user_id=(?<str>[0-9]+)").Groups["str"].Value;
                "screen_name"        = [System.Text.RegularExpressions.Regex]::Match($result, "user_id=(?<str>[0-9a-zA-Z_]+)").Groups["str"].Value
            }
            
            if ($authinfo["oauth_token"] -eq "") {
                <# Retry #>
                Write-Host "access token fail."
                Login $request
            }
            else {
                <# Success #>
                $request.OauthTokenSecret = $authinfo["oauth_token_secret"]
                Write-Host $oauth_callback_confirmed
                return $authinfo
            }
        }
        else {
            <# Retry #>
            Login($request)
        }
    }
    else {
        <# Retry #>
        Login($request)
    }
}

[System.Net.Http.HttpClient]$httpClient = New-Object -TypeName System.Net.Http.HttpClient
[Settings]$settings = [Settings]::new()

$request = [Request]::new($settings.apiKey, $settings.apiSecret,
    [Endpoint]::requestTokenUrl, [Endpoint]::authorizeUrl, [Endpoint]::accessTokenUrl, $httpClient)

[Hashtable]$authInfo = $null

try {
    $Error.Clear()
    $authInfo = Login $request
}
catch [Exception] {
    Write-Host $Error
}

$api = [TwitterApi]::new($request, $settings.apiKey, $authInfo["oauth_token"], $authInfo["user_id"], $authInfo["screen_name"])

:loop while ($true) {
    $command = Read-Host "Input command."
    $commands = -split $command
    [Command]::ParseCommand($api, $commands)
    continue loop
}


Class Command {
    static [void] ParseCommand([TwitterApi]$api, [string[]]$commands) {
        switch ($commands[0].ToLower()) {
            "home" {
                $result = $api.HomeTL($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK) {
                    [V1Status[]]$statuses = [System.Text.Json.JsonSerializer]::Deserialize($json, [V1Status[]], [Helper]::GetJsonSerializerOptions())
                    [array]::Reverse($statuses)        
                    foreach ($status in $statuses) {
                        [Display]::V1DisplayTweet($status)
                    }
                }
                else {
                    [V1ErrorResponse]$errorResponse = [System.Text.Json.JsonSerializer]::Deserialize($json, [V1ErrorResponse], [Helper]::GetJsonSerializerOptions())
                    foreach ($e in $errorResponse.errors) {
                        Write-Host $e.message                    
                    }    
                }
            }
    
            "lookup" {
                $result = $api.Lookup($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK) {
                    [Tweet]$tweet = [System.Text.Json.JsonSerializer]::Deserialize($json, [Tweet], [Helper]::GetJsonSerializerOptions())
                    [Display]::DisplayTweet($tweet)
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }            
            }
    
            "users_by_username" {
                $result = $api.ByUserName($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
    
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK) {
                    [UsersResponse]$user = [System.Text.Json.JsonSerializer]::Deserialize($json, [UsersResponse], [Helper]::GetJsonSerializerOptions())
                    if ($null -ne $user.data) {                
                        [Display]::DisplayUser($user)
                    }
                    else {
                        [Display]::DisplayErrors($user.errors)
                    }
                }
                else {
                    Write-Host("/2/users/by/username API returned an error.") -ForegroundColor DarkRed
                    [Display]::DisplayError($statusCode, $json)
                }  
            }
    
            "users_tweets" {
                $result = $api.UsersTweets($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
    
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK) {
                    [Timeline]$timeline = [System.Text.Json.JsonSerializer]::Deserialize($json, [Timeline], [Helper]::GetJsonSerializerOptions())
                    if ($null -ne $timeline.data) {                
                        [Display]::DisplayTimeline($timeline)
                    }
                    else {
                        [Display]::DisplayErrors($timeline.errors)
                    }
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }
            }
    
            "post_tweets" {
                $result = $api.PostTweets($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Created) {
                    [PostTweetsResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [PostTweetsResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.text) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }    
            }
    
            "delete_tweets" {
                $result = $api.DeleteTweets($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Accepted -or $statusCode -eq [System.Net.HttpStatusCode]::NoContent) {
                    [DeleteTweetsResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [DeleteTweetsResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.deleted) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }    
            }
    
            "post_retweets" {
                $result = $api.PostRetweets($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Created) {
                    [RetweetsResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [RetweetsResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.retweeted) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }    
            }
    
            "delete_retweets" {
                $result = $api.DeleteRetweets($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Created) {
                    [RetweetsResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [RetweetsResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.retweeted) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }   
            }
    
            "post_likes" {
                $result = $api.PostLikes($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Created) {
                    [LikesResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [LikesResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.liked) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }    
            }
    
            "delete_likes" {
                $result = $api.DeleteLikes($commands)
                [System.Net.HttpStatusCode]$statusCode = $result["statusCode"]
                $json = $result["body"]
                
                if ($statusCode -eq [System.Net.HttpStatusCode]::OK -or $statusCode -eq [System.Net.HttpStatusCode]::Created) {
                    [LikesResponse]$response = [System.Text.Json.JsonSerializer]::Deserialize($json, [LikesResponse], [Helper]::GetJsonSerializerOptions())
                    Write-Host($response.data.liked) -ForegroundColor DarkMagenta
                }
                else {
                    [Display]::DisplayError($statusCode, $json)
                }    
            }
    
            default {
                Write-Host "input valid command. ex) > home"
            }
        }
    }
}


class Request {

    [string]$ApiKey
    [string]$ApiSecretKey
    [string]$RequestTokenUrl
    [string]$AuthorizeUrl
    [string]$AccessTokenUrl
    [System.Net.Http.HttpClient]$Client
    [string]$OauthTokenSecret

    Request(
        [string]$apiKey,
        [string]$apiSecretKey,
        [string]$requestTokenUrl,
        [string]$authorizeUrl,
        [string]$accessTokenUrl,
        [System.Net.Http.HttpClient]$client
    ) {
        $this.ApiKey = $apiKey
        $this.ApiSecretKey = $apiSecretKey
        $this.RequestTokenUrl = $requestTokenUrl
        $this.AuthorizeUrl = $authorizeUrl
        $this.AccessTokenUrl = $accessTokenUrl
        $this.Client = $client
        $this.OauthTokenSecret = $null
    }

    [System.String] UrlEncode([string]$str) {
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

    [System.String] GetSignKey() {
        return $this.UrlEncode($this.ApiSecretKey) + "&" + $this.UrlEncode($this.OauthTokenSecret)
    }

    [System.String] GetSignatureBaseString(
        [string]$httpMethod, 
        [string]$url, 
        [Hashtable]$hashtable
    ) {
        [string]$str += $this.UrlEncode($httpMethod) + "&" + $this.UrlEncode($url)
        [string]$c = ""
        foreach ($key in $hashtable.keys | Sort-Object ) {
            $c += $key + "=" + $hashtable[$key] + "&"
        }
        $c = $c.Substring(0, $c.Length - 1)
        [string]$encoded = $this.UrlEncode($c)
        $str += "&" + $encoded
        return $str
    }

    [System.String] GetHMACSHA(
        [string]$signKey, 
        [string]$signatureBaseString
    ) {
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA1
        $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($signKey)
        $hash = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($signatureBaseString))
        $base64 = [System.Convert]::ToBase64String($hash)
        $signature = $this.UrlEncode($base64)
        return $signature;
    }

    [Hashtable] PostRequest(
        [string]$url, 
        [Hashtable]$auth, 
        [Hashtable]$contents
    ) {
        if ($contents.Length -gt 0) {
            foreach ($key in $contents.keys) {
                $auth[$key] = $this.UrlEncode($contents[$key])
            }
        }
        $signature = $this.GetHMACSHA(
            $this.GetSignKey(),
            $this.GetSignatureBaseString("POST", $url, $auth)
        )
        $header = "OAuth "
        foreach ($key in $auth.keys | Sort-Object) {
            if ($key.StartsWith("oauth_")) {
                $value = $this.UrlEncode($auth[$key])
                $header += $key + "=""" + $value + ""","
            }
        }
        $header += "oauth_signature=""" + $signature + """"
        [string]$post = "";
        foreach ($key in $contents.keys | Sort-Object) {
            $post += $this.UrlEncode($key) + "=" + $this.UrlEncode($contents[$key]) + "&"
        }
        if ($post -ne "") {
            $post = $post.Substring(0, $post.Length - 1)
        }
        $this.Client.DefaultRequestHeaders.Authorization = $header
        $httpContent = New-Object -TypeName System.Net.Http.StringContent($post, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.PostAsync($url, $httpContent)
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        return @{
            "statusCode" = $response.StatusCode;
            "body"       = $response.Content.ReadAsStringAsync().Result
        }
    }

    [Hashtable] PostRequestJson(
        [string]$url, 
        [Hashtable]$auth, 
        [string]$json
    ) {
        $signature = $this.GetHMACSHA(
            $this.GetSignKey(),
            $this.GetSignatureBaseString("POST", $url, $auth)
        )
        $header = "OAuth "
        foreach ($key in $auth.keys | Sort-Object) {
            if ($key.StartsWith("oauth_")) {
                $value = $this.UrlEncode($auth[$key])
                $header += $key + "=""" + $value + ""","
            }
        }
        $header += "oauth_signature=""" + $signature + """"
        $this.Client.DefaultRequestHeaders.Authorization = $header
        $httpContent = New-Object -TypeName System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, "application/json")

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.PostAsync($url, $httpContent)
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        return @{
            "statusCode" = $response.StatusCode;
            "body"       = $response.Content.ReadAsStringAsync().Result
        }
    }

    [Hashtable] GetRequest(
        [string]$url, 
        [Hashtable]$auth, 
        [Hashtable]$contents
    ) {
        $query = ""
        if ($contents.Length -gt 0) {
            foreach ($key in $contents.keys) {
                $query += $this.UrlEncode($key) + "=" + $this.UrlEncode($contents[$key]) + "&"
                $auth[$key] = $this.UrlEncode($contents[$key])
            }
        }
        $signature = $this.GetHMACSHA(
            $this.GetSignKey(),
            $this.GetSignatureBaseString("GET", $url, $auth)
        )
        if ($query.Length -gt 0) {
            $query = $query.Substring(0, $query.Length - 1)
            $url = $url + "?" + $query
        }
        $header = "OAuth "
        foreach ($key in $auth.keys | Sort-Object) {
            $value = $this.UrlEncode($auth[$key])
            $header += $key + "=""" + $value + ""","
        }
        $header += "oauth_signature=""" + $signature + """"
        $this.Client.DefaultRequestHeaders.Authorization = $header

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.GetAsync($url)
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        
        return @{
            "statusCode" = $response.StatusCode;
            "body"       = $response.Content.ReadAsStringAsync().Result
        }
    }

    [Hashtable] DeleteRequest(
        [string]$url, 
        [Hashtable]$auth
    ) {
        $signature = $this.GetHMACSHA(
            $this.GetSignKey(),
            $this.GetSignatureBaseString("DELETE", $url, $auth)
        )
        $header = "OAuth "
        foreach ($key in $auth.keys | Sort-Object) {
            $value = $this.UrlEncode($auth[$key])
            $header += $key + "=""" + $value + ""","
        }
        $header += "oauth_signature=""" + $signature + """"
        $this.Client.DefaultRequestHeaders.Authorization = $header

        $task = $null
        try {
            $Error.Clear()
            $task = $this.Client.DeleteAsync($url)
            $task.Wait()
        }
        catch [Exception] {
            Write-Host $Error
        }

        $response = $task.Result
        
        return @{
            "statusCode" = $response.StatusCode;
            "body"       = $response.Content.ReadAsStringAsync().Result
        }
    }

}


class TwitterApi {

    [Request]$Request
    [string]$OAuthToken
    [string]$ApiKey
    [string]$UserId
    [string]$ScreenName

    TwitterApi(
        [Request]$request,
        [string]$apiKey,
        [string]$oauthToken,
        [string]$userId,
        [string]$screenName
    ) {
        $this.Request = $request
        $this.ApiKey = $apiKey
        $this.OAuthToken = $oauthToken
        $this.UserId = $userId
        $this.ScreenName = $screenName
    }

    [Hashtable] AuthParams() {
        return @{
            "oauth_consumer_key"     = $this.ApiKey;
            "oauth_nonce"            = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_token"            = $this.OAuthToken;
            "oauth_timestamp"        = [Helper]::GetTimeStamp();
            "oauth_version"          = "1.0"
        }
    }

    [Hashtable] HomeTL([string[]]$commands) {
        $params = @{}
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "count" {
                            $i = $p[1] -as [Int32]
                            if ($i -ge 1 -and $i -le 200) {
                                $params["count"] = $i
                            }
                        }
                        "since_id" {
                            $i = $p[1] -as [Int64]
                            if ($i) {
                                $params["since_id"] = $i
                            }
                        }
                        "max_id" {
                            $i = $p[1] -as [Int64]
                            if ($i) {
                                $params["max_id"] = $i
                            }
                        }
                        "trim_user" {
                            if ($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false") {
                                $params["trim_user"] = $p[1].ToLower()
                            }
                        }
                        "exclude_replies" {
                            if ($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false") {
                                $params["exclude_replies"] = $p[1].ToLower()
                            }
                        }
                        default {
                            $params[[string]$p] = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.GetRequest([Endpoint]::homeTimeline, $this.AuthParams(), $params)
    }

    [Hashtable] Lookup([string[]]$commands) {
        $params = @{
            "tweet.fields" = "attachments,author_id,context_annotations,conversation_id,lang,in_reply_to_user_id,id,geo,entities,created_at,possibly_sensitive,withheld,text,source,referenced_tweets,public_metrics";
            "expansions"   = "attachments.media_keys,attachments.poll_ids,entities.mentions.username,referenced_tweets.id,referenced_tweets.id.author_id,geo.place_id,in_reply_to_user_id,author_id";
            "media.fields" = "type,duration_ms,media_key,height,preview_image_url,url,alt_text,width,public_metrics";
            "place.fields" = "contained_within,name,place_type,country,country_code,full_name,geo,id";
            "poll.fields"  = "voting_status,options,end_datetime,id,duration_minutes";
            "user.fields"  = "created_at,description,pinned_tweet_id,username,verified,withheld,protected,id,entities,profile_image_url,location,public_metrics,name,url";
        }
        [string]$id = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "id" {
                            $id = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.GetRequest([Endpoint]::tweets + "/" + $id, $this.AuthParams(), $params)
    }

    [Hashtable] ByUserName([string[]]$commands) {
        $params = @{
            "expansions"   = "pinned_tweet_id";
            "tweet.fields" = "attachments,author_id,context_annotations,conversation_id,created_at,entities,geo,id,in_reply_to_user_id,lang,public_metrics,possibly_sensitive,referenced_tweets,reply_settings,source,text,withheld";
            "user.fields"  = "created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url,protected,public_metrics,url,username,verified,withheld";
        }
        [string]$username = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "username" {
                            $username = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.GetRequest([Endpoint]::byUsername + "/" + $username, $this.AuthParams(), $params)
    }

    [Hashtable] UsersTweets([string[]]$commands) {
        $params = @{
            "expansions"   = "attachments.poll_ids,attachments.media_keys,author_id,entities.mentions.username,geo.place_id,in_reply_to_user_id,referenced_tweets.id,referenced_tweets.id.author_id";
            "place.fields" = "contained_within,country,country_code,full_name,geo,id,name,place_type";
            "poll.fields"  = "duration_minutes,end_datetime,id,options,voting_status";
            "tweet.fields" = "attachments,author_id,context_annotations,conversation_id,created_at,entities,geo,id,in_reply_to_user_id,lang,public_metrics,possibly_sensitive,referenced_tweets,reply_settings,source,text,withheld"
            "user.fields"  = "created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url,protected,public_metrics,url,username,verified,withheld"
        }
        [string]$id = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "id" {
                            $id = $p[1]
                        }
                        "max_results" {
                            $i = $p[1] -as [Int64]
                            if ($i) {
                                $params["max_results"] = $i
                            }
                        }
                        default {
                            $params[[string]$p] = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.GetRequest([Endpoint]::users + "/" + $id + "/tweets" , $this.AuthParams(), $params)
    }


    [Hashtable] PostTweets([string[]]$commands) {
        $entity = [PostTweets]::new()
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "text" {
                            $entity.text = $p[1]
                            $ci = $index + 1
                            for ($ci; $ci -lt $commands.Length; $ci++) {
                                $tq = $commands[$ci].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                                $ignore = @("status", "direct_message_deep_link", "for_super_followers_only", "geo.place_id", "quote_tweet_id", "reply.in_reply_to_tweet_id", "reply_settings")
                                if ( -not ($ignore -contains ([string]$tq[0]).ToLower()) ) {
                                    $entity.text += " " + $commands[$ci]
                                    $index++
                                }
                            }
                        }
                        "direct_message_deep_link" {
                            $entity.direct_message_deep_link = $p[1]
                        }
                        "for_super_followers_only" {
                            if ($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false") {
                                $entity.for_super_followers_only = $p[1]
                            }
                        }
                        "geo.place_id" {
                            $entity.geo = [Geo]::new()
                            $entity.geo.place_id = $p[1]
                        }
                        "quote_tweet_id" {
                            $entity.quote_tweet_id = $p[1]
                        }
                        "reply.in_reply_to_tweet_id" {
                            $entity.reply = [PostReply]::new()
                            $entity.reply.in_reply_to_tweet_id = $p[1]
                        }
                        "reply_settings" {
                            $entity.reply_settings = $p[1]
                        }

                    }
                }
            }
        }

        $json = [System.Text.Json.JsonSerializer]::Serialize($entity, [Helper]::GetJsonSerializerOptions())
        return $this.Request.PostRequestJson([Endpoint]::tweets, $this.AuthParams(), $json)
    }

    [Hashtable] DeleteTweets([string[]]$commands) {
        [string]$id = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "id" {
                            $id = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.DeleteRequest([Endpoint]::tweets + "/" + $id, $this.AuthParams())
    }

    [Hashtable] PostRetweets([string[]]$commands) {
        $entity = [PostRetweets]::new()
        [string]$tweetId = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "tweet_id" {
                            $tweetId = $p[1]
                        }
                    }
                }
            }
        }
        $entity.tweet_id = $tweetId
        $json = [System.Text.Json.JsonSerializer]::Serialize($entity, [Helper]::GetJsonSerializerOptions())
        return $this.Request.PostRequestJson([Endpoint]::users + "/" + $this.UserId + "/retweets", $this.AuthParams(), $json)
    }

    [Hashtable] DeleteRetweets([string[]]$commands) {
        [string]$sourceTweetId = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "source_tweet_id" {
                            $sourceTweetId = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.DeleteRequest([Endpoint]::users + "/" + $this.UserId + "/retweets/" + $sourceTweetId, $this.AuthParams())
    }

    [Hashtable] PostLikes([string[]]$commands) {
        $entity = [PostLikes]::new()
        [string]$tweetId = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "tweet_id" {
                            $tweetId = $p[1]
                        }
                    }
                }
            }
        }
        $entity.tweet_id = $tweetId
        $json = [System.Text.Json.JsonSerializer]::Serialize($entity, [Helper]::GetJsonSerializerOptions())
        return $this.Request.PostRequestJson([Endpoint]::users + "/" + $this.UserId + "/likes", $this.AuthParams(), $json)
    }

    [Hashtable] DeleteLikes([string[]]$commands) {
        [string]$tweetId = $null
        if ($commands.Length -gt 1) {
            for ($index = 1; $index -lt $commands.Length; $index++) {
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if ($p.Length -eq 2) {
                    switch (([string]$p[0]).ToLower()) {
                        "tweet_id" {
                            $tweetId = $p[1]
                        }
                    }
                }
            }
        }
        return $this.Request.DeleteRequest([Endpoint]::users + "/" + $this.UserId + "/likes/" + $tweetId, $this.AuthParams())
    }

}

class Display {

    static [void] V1DisplayTweet([V1Status]$status) {        
        if ($null -ne $status.retweeted_status) {
            $retweetedStatus = $status.retweeted_status
            Write-Host(
                $retweetedStatus.user.name + " @" + $retweetedStatus.user.screen_name `
                    + " ReTweeted by " + $status.user.name + " @" `
                    + $status.user.screen_name
            ) -ForegroundColor DarkYellow
            Write-Host([Display]::UnEscape($retweetedStatus.text)) -ForegroundColor DarkGreen
            $source = [Display]::ReplaceSource($retweetedStatus.source)
            $dt = [Display]::ConvertTimeZone($retweetedStatus.created_at)
            Write-Host($dt + " from " + $source + " id:" + $retweetedStatus.id_str) -ForegroundColor DarkGray
        }
        else {
            $tweetUser = $status.user
            Write-Host($tweetUser.name + " @" + $tweetUser.screen_name) -ForegroundColor Cyan
            Write-Host([Display]::UnEscape($status.text)) -ForegroundColor White
            $source = [Display]::ReplaceSource($status.source)
            $dt = [Display]::ConvertTimeZone($status.created_at)
            Write-Host($dt + " from " + $source + " id:" + $status.id_str) -ForegroundColor DarkGray
        }
    }

    static [void] DisplayTweet([Tweet]$tweet) {
        [TimelineInclude]$includes = $tweet.includes
        [User[]]$users = $includes.users
        [User]$user = $users[0]
        Write-Host($user.name + " @" + $user.username) -ForegroundColor Cyan
        Write-Host([Display]::UnEscape($tweet.data.text)) -ForegroundColor White
        if ($null -ne $tweet.data.referenced_tweets -and $tweet.data.referenced_tweets.Length -gt 0) {
            foreach ($referencedTweet in $tweet.data.referenced_tweets) {
                Write-Host($referencedTweet.type + ":" + $referencedTweet.id)  -ForegroundColor DarkGray
            }  
        }
        Write-Host($tweet.data.created_at.LocalDateTime.ToString() + " from " + $tweet.data.source + " id:" + $tweet.data.id) -ForegroundColor DarkGray
    }

    static [void] DisplayUser([UsersResponse]$user) {
        Write-Host($user.data.name + " @" + $user.data.username) -ForegroundColor Cyan
        Write-Host("location:" + $user.data.location)
        Write-Host("description:" + $user.data.description)
        Write-Host("profile_image_url:" + $user.data.profile_image_url)
        if ($null -ne $user.data.pinned_tweet_id) {
            Write-Host("pinned_tweet_id:" + $user.data.pinned_tweet_id)
        }
        Write-Host("created_at:" + $user.data.created_at.LocalDateTime.ToString() + " / id:" + $user.data.id) -ForegroundColor DarkGray        
    }

    static [void] DisplayTimeline([Timeline]$timeline) {
        [TimelineDatum[]]$data = $timeline.data
        [User[]]$users = $timeline.includes.users

        [array]::Reverse($data)        

        foreach ($datum in $data) {
            [User]$user = [System.Linq.Enumerable]::FirstOrDefault($users, [Func[User, bool]] { param($u) $u.id -eq $datum.author_id })

            if ($null -ne $datum.referenced_tweets -and $datum.referenced_tweets.Length -gt 0 -and $datum.referenced_tweets[0].type -eq "retweeted") {
                [TimelineDatum]$referenceTweet = [System.Linq.Enumerable]::FirstOrDefault($timeline.includes.tweets, [Func[TimelineDatum, bool]] { param($t) $t.id -eq $datum.referenced_tweets[0].id })
                [User]$referenceUser = [System.Linq.Enumerable]::FirstOrDefault($users, [Func[User, bool]] { param($u) $u.id -eq $referenceTweet.author_id }) 
                Write-Host(
                    $referenceUser.name + " @" + $referenceUser.username `
                        + " ReTweeted by " + $user.data.name + " @" + $user.data.username
                ) -ForegroundColor DarkYellow
                Write-Host([Display]::UnEscape($referenceTweet.text)) -ForegroundColor DarkGreen
                Write-Host($referenceTweet.created_at.LocalDateTime.ToString() + " from " + $referenceTweet.source + " id:" + $referenceTweet.id) -ForegroundColor DarkGray
            }
            else {
                Write-Host($user.name + " @" + $user.username) -ForegroundColor Cyan
                Write-Host([Display]::UnEscape($datum.text)) -ForegroundColor White
                Write-Host($datum.created_at.LocalDateTime.ToString() + " from " + $datum.source + " id:" + $datum.id) -ForegroundColor DarkGray
            }
        }
    }


    static [void] DisplayError([System.Net.HttpStatusCode]$statusCode, [string]$json) {
        if ($statusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            Write-Host("Not Found error was returned.") -ForegroundColor DarkRed
        }
        else {
            [ErrorResponse]$errorResponse = [System.Text.Json.JsonSerializer]::Deserialize($json, [ErrorResponse], [Helper]::GetJsonSerializerOptions())
            Write-Host($errorResponse.title) -ForegroundColor DarkRed
            Write-Host($errorResponse.detail) -ForegroundColor DarkRed
        }
    }

    static [void] DisplayErrors([ErrorResponseError[]]$errors) {
        foreach ($e in $errors) {
            Write-Host($e.title) -ForegroundColor DarkRed
            Write-Host($e.detail) -ForegroundColor DarkRed            
        }
    }


    static [string] UnEscape([string]$status) {
        return $status -replace "&gt;", ">" -replace "&lt;", "<" -replace "&amp;", "&"
    }

    static [string] ReplaceSource([string]$source) {
        return [System.Text.RegularExpressions.Regex]::Match($source, "rel=""nofollow"">(?<str>.+)</a>").Groups["str"].Value;
    }

    static [string] ConvertTimeZone([string]$twitterDate) {
        return [string][System.DateTimeOffset]::ParseExact($twitterDate, "ddd MMM dd HH:mm:ss zzz yyyy", `
                [System.Globalization.CultureInfo]::InvariantCulture).LocalDateTime
    }
    
}


class V1Status {
    [string]$created_at
    [Int64]$id
    [string]$id_str
    [string]$text
    [bool]$truncated
    [V1Entities]$entities
    [string]$source
    [System.Nullable[Int64]]$in_reply_to_status_id
    [string]$in_reply_to_status_id_str
    [System.Nullable[Int64]]$in_reply_to_user_id
    [string]$in_reply_to_user_id_str
    [string]$in_reply_to_screen_name
    [V1User]$user
    [V1Geo]$geo
    [V1Geo]$coordinates
    [V1Place]$place
    [string]$contributors
    [V1Status]$retweeted_status
    [bool]$is_quote_status
    [Int64]$retweet_count
    [Int64]$favorite_count
    [bool]$favorited
    [bool]$retweeted
    [string]$lang
}

class V1Entities {
    [V1Hashtag[]]$hashtags
    [string[]]$symbols
    [V1UserMention[]]$user_mentions
    [V1Url[]]$urls
}

class V1User {
    [Int64]$id
    [string]$id_str
    [string]$name
    [string]$screen_name
    [string]$location
    [string]$description
    [string]$url
    [V1UserEntities]$entities
    [bool]$protected
    [Int64]$followers_count
    [Int64]$friends_count
    [Int64]$listed_count
    [string]$created_at
    [Int64]$favourites_count
    [string]$utc_offset
    [string]$time_zone
    [bool]$geo_enabled
    [bool]$verified
    [Int64]$statuses_count
    [string]$lang
    [bool]$contributors_enabled
    [bool]$is_translator
    [bool]$is_translation_enabled
    [string]$profile_background_color
    [string]$profile_background_image_url
    [string]$profile_background_image_url_https
    [bool]$profile_background_tile
    [string]$profile_image_url
    [string]$profile_image_url_https
    [string]$profile_banner_url
    [string]$profile_link_color
    [string]$profile_sidebar_border_color
    [string]$profile_sidebar_fill_color
    [string]$profile_text_color
    [bool]$profile_use_background_image
    [bool]$has_extended_profile
    [bool]$default_profile
    [bool]$default_profile_image
    [bool]$following
    [bool]$follow_request_sent
    [bool]$notifications
    [string]$translator_type
    [string[]]$withheld_in_countries
}

class V1Geo {
    [string]$type
    [double[]]$coordinates
}

class V1Place {
    [string]$id
    [string]$url
    [string]$place_type
    [string]$name
    [string]$full_name
    [string]$country_code
    [string]$country
    [V1Geo]$geometry
    [double[]]$polylines
    [double[]]$centroid
    [V1GeoAttribute]$attributes
}

class V1GeoAttribute {
    [string]$geotagCount
    [string]$162834:id
}


class V1UserEntities {
    [V1UserEntityUrl]$url
    [V1UserEntityDescription]$description
}

class V1UserEntityUrl {
    [V1Url[]]$urls
}

class V1UserEntityDescription {
    [V1Url[]]$urls
}

class V1UserMention {
    [string]$screen_name
    [string]$name
    [Int64]$id
    [string]$id_str
    [Int32[]]$indices
}

class V1Url {
    [string]$url
    [string]$expanded_url
    [string]$display_url
    [Int32[]]$indices
}

class V1Hashtag {
    [string]$text
    [Int32[]]$indices
}


class V1ErrorResponse {
    [V1ErrorResponseEntity[]]$errors
}

class V1ErrorResponseEntity {
    [string]$parameter
    [string]$details
    [string]$code
    [string]$value
    [string]$message
}


# ここから下はv2

class Tweet {
    [TimelineDatum]$data
    [TimelineInclude]$includes
}
  
class Timeline {
    [TimelineDatum[]]$data
    [TimelineInclude]$includes
    [Meta]$meta
    [ErrorResponseError[]]$errors
}
  
class TimelineDatum {
    [PublicMetrics]$public_metrics
    [string]$source
    [Entity]$entities
    [string]$id
    [ReferencedTweets[]]$referenced_tweets
    [string]$conversation_id
    [string]$text
    [string]$author_id
    [System.DateTimeOffset]$created_at
    [string]$reply_settings
    [string]$lang
    [ContextAnnotations[]]$context_annotations
    [bool]$possibly_sensitive
    [Attachments]$attachments
    [Geo]$geo
    [string]$in_reply_to_user_id
    [NonPublicMetrics]$non_public_metrics
    [OrganicMetrics]$organic_metrics
    [OrganicMetrics]$promoted_metrics
    [Withheld]$withheld
}
  
class UserEntityUrl {
    [Url[]]$urls
}
  
class UserEntityDescription {
    [Url[]]$urls
}
  
class NonPublicMetrics {
    [Int64]$impression_count
    [Int64]$url_link_clicks
    [Int64]$user_profile_clicks
}
  
class OrganicMetrics {
    [Int64]$impression_count
    [Int64]$like_count
    [Int64]$reply_count
    [Int64]$retweet_count
    [Int64]$url_link_clicks
    [Int64]$user_profile_clicks
}
  
class PublicMetrics {
  
    [Int64]$retweet_count
    [Int64]$reply_count
    [Int64]$like_count
    [Int64]$quote_count
    [Int64]$followers_count
    [Int64]$following_count
    [Int64]$tweet_count
    [Int64]$listed_count
  
}
  
class ContextAnnotations {
    [Domain]$domain
    [Domain]$entity
}
  
class Domain {
    [string]$id
    [string]$name
    [string]$description
}
  
class ReferencedTweets {
    [string]$type
    [string]$id
}
  
class Withheld {
    [bool]$copyright
    [string[]]$country_codes
}
  
class Annotation {
    [Int32]$start
    [Int32]$end
    [double]$probability
    [string]$type
    [string]$normalized_text
}
  
class Mention {
    [Int32]$start
    [Int32]$end
    [string]$username
    [string]$id
}
  
class Entity {
    [Annotation[]]$annotations
    [Mention[]]$mentions
    [Url[]]$urls
    [Hashtag[]]$cashtags
    [Hashtag[]]$hashtags
}
  
class Geo {
    [Coordinates]$coordinates
    [string]$place_id
}
  
class Coordinates {
    [string]$type
    [double]$coordinates
} 
  
class Url {
    [Int32]$start
    [Int32]$end
    [string]$url
    [string]$expanded_url
    [string]$display_url
    [Int32]$status
    [string]$title
    [string]$description
    [string]$unwound_url
}
  
class Hashtag {
    [Int32]$start
    [Int32]$end
    [string]$tag
}
  
class Attachments {
    [string[]]$media_keys
}
  
class Media {
    [string]$url
    [Int32]$width
    [Int32]$height
    [string]$type
    [string]$media_key
}
  
class Meta {
    [string]$oldest_id
    [string]$newest_id
    [Int64]$result_count
    [string]$next_token
}
  
class TimelineInclude {
    [User[]]$users
    [TimelineDatum[]]$tweets
    [Media[]]$media
}

  
class User {
    [string]$name
    [string]$pinned_tweet_id
    [UserEntities]$entities
    [bool]$protected
    [string]$profile_image_url
    [string]$description
    [string]$location
    [string]$username
    [string]$url
    [PublicMetrics]$public_metrics
    [System.DateTimeOffset]$created_at
    [bool]$verified
    [string]$id
}
  
class UserEntities {
    [UserEntityUrl]$url
    [UserEntityDescription]$description
}

class ErrorResponse {
    [string]$title
    [string]$detail
    [string]$type
}

class ErrorResponseError {
    [string]$value
    [string]$detail
    [string]$title
    [string]$resource_type
    [string]$parameter
    [string]$resource_id
    [string]$type
}

class PostTweets {
    [string]$text
    [string]$direct_message_deep_link
    [string]$for_super_followers_only
    [Geo]$geo
    [PostMedia]$media
    [PostPoll]$poll
    [string]$quote_tweet_id
    [PostReply]$reply
    [string]$reply_settings
}

class PostMedia {
    [string[]]$media_ids
    [string[]]$tagged_user_ids
}

class PostPoll {
    [string[]]$options
    [Int32]$duration_minutes
}

class PostReply {
    [string]$in_reply_to_tweet_id
    [string[]]$exclude_reply_user_ids
}


class PostTweetsResponse {
    [PostTweetsResponseData]$data
}

class PostTweetsResponseData {
    [string]$id
    [string]$text
}

class DeleteTweetsResponse {
    [DeleteTweetsResponseData]$data
}

class DeleteTweetsResponseData {
    [bool]$deleted
}

class PostRetweets {
    [string]$tweet_id
}

class RetweetsResponse {
    [RetweetsResponseData]$data
}

class RetweetsResponseData {
    [bool]$retweeted
}

class PostLikes {
    [string]$tweet_id
}

class LikesResponse {
    [LikesResponseData]$data
}

class LikesResponseData {
    [bool]$liked
}

class UsersResponse {
    [User]$data
    [UsersResponseInclude]$includes
    [ErrorResponseError[]]$errors
}

class UsersResponseInclude {
    [TimelineDatum]$tweets
}


class Helper {
    static [int] GetTimeStamp() {
        return [int]::Parse($(Get-Date -date (Get-Date).ToUniversalTime()-uformat %s))
    }
    static [System.Text.Json.JsonSerializerOptions] GetJsonSerializerOptions() {
        $options = [System.Text.Json.JsonSerializerOptions]::new()
        $options.DefaultIgnoreCondition = [System.Text.Json.Serialization.JsonIgnoreCondition]::WhenWritingNull
        return $options
    }
}


class Endpoint {
    #static [string]$authorizeUrl = "https://twitter.com/i/oauth2/authorize"
    static [string]$oauth2TokenUrl = "https://api.twitter.com/2/oauth2/token"
    static [string]$requestTokenUrl = "https://api.twitter.com/oauth/request_token"
    static [string]$authorizeUrl = "https://api.twitter.com/oauth/authorize"
    static [string]$accessTokenUrl = "https://api.twitter.com/oauth/access_token"

    static [string]$homeTimeline = "https://api.twitter.com/1.1/statuses/home_timeline.json"

    static [string]$tweets = "https://api.twitter.com/2/tweets"
    static [string]$byUsername = "https://api.twitter.com/2/users/by/username"
    static [string]$users = "https://api.twitter.com/2/users"
}

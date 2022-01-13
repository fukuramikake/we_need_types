# PowerShell 7 で Twitter するやつ

PowerShell 7 で Twitter v2 API を叩いたりするやつです。  
前に作ってたやつは .NET Core 以降、System.Web.Script.Serialization が使えなくなったとか色々あって作り直しました。  
OAuth 2.0 への対応は手元では実装の確認はできてるのですが、Home Timeline API がまだ v2 に来ていないため、現状では OAuth 1.0a を利用しています。

## 利用方法

### API Key, API Secretの設定

`pwsh7_twitter.ps1` の以下の行にTwitter AppsのAPI KeyとAPI Secretを設定する必要があります。  

```powershell
[string]$apiKey = ""
[string]$apiSecret = ""
```

または、環境変数 `TWITTER_API_KEY` と `TWITTER_API_SECRET` に値を設定しても良いです。

```powershell
if ($null -ne $env:TWITTER_API_KEY) {
    $this.apiKey = $env:TWITTER_API_KEY
}
if ($null -ne $env:TWITTER_API_SECRET) {
    $this.apiSecret = $env:TWITTER_API_SECRET
}
```

TwitterのApp登録は以下のURLからどうぞ。  
https://developer.twitter.com/

### 起動方法

PowerShell 7 以降で、`pwsh7_twitter.ps1` を実行します。  
`> .\pwsh7_twitter.ps1`  
コンソールにURLが表示され、可能な場合はデフォルトブラウザで連携アプリを認証するためのURLが開かれます。  
連携アプリを認証すると、PINが表示されるので、コンソールに入力します。  
`Input pin code.: 1234567`  
認証が完了すると、各Twitter APIを実行するコマンドを入力できるようになります。  
`Input command.: `

### 対応しているAPI呼び出しコマンド

#### **home**

Twitter API v1 の `GET statuses/home_timeline` APIを叩き、タイムラインを表示します。本API以外はすべてTwitter API v2を利用しています。(Home Timeline APIはまだv2用が公開されていないため)

`Input command.: home count:100`

#### **lookup**

`GET /2/tweets/:id` APIを叩き、ツイートを表示します。

`Input command.: lookup id:1234567890123456789`

#### **users_by_username**

`GET /2/users/by/username/:username` APIを叩き、指定したusernameのユーザ情報を表示します。ユーザの表示名からidを求めたいとき等に使います。idは最後の表示行にグレーで表示されます。

`Input command.: users_by_username username:twitterjp`

#### **users_tweets**

`GET /2/users/:id/tweets` APIを叩き、指定したユーザのツイートを表示します。

`Input command.: users_tweets id:7080152 max_results:20`  

#### **users_mentions**

`GET /2/users/:id/mentions` APIを叩き、指定したユーザに言及するツイートを表示します。

`Input command.: users_mentions id:7080152 max_results:20`  

#### **post_tweets**

`POST /2/tweets` APIを叩き、ツイートを投稿します。

`Input command.: post_tweets text:テスト`  

別の自身、あるいは別のアカウントのツイートに投稿を繋げる場合は、`reply.in_reply_to_tweet_id` で該当のツイートのIDを指定します。

`post_tweets text:繋げる reply.in_reply_to_tweet_id:1234567890123456789`

#### **delete_tweets**

`DELETE /2/tweets/:id` APIを叩き、ツイートを削除します。

`Input command.: delete_tweet id:1234567890123456789`  

#### **post_retweets**

`POST /2/users/:id/retweets` APIを叩き、リツイートします。このAPIはキー名が `tweet_id` です。

`Input command.: post_retweets tweet_id:1234567890123456789`  

#### **delete_retweets**

`DELETE /2/users/:id/retweets/:source_tweet_id` APIを叩き、リツイートします。このAPIはキー名が `source_tweet_id` です。

`Input command.: delete_retweets source_tweet_id:1234567890123456789`  

#### **post_likes**

`POST /2/users/:id/likes` APIを叩き、ファボします。このAPIはキー名が `tweet_id` です。

`Input command.: post_likes tweet_id:1234567890123456789`  

#### **delete_likes**

`DELETE /2/users/:id/likes/:tweet_id` APIを叩き、ファボを解除します。このAPIはキー名が `tweet_id` です。

`Input command.: delete_likes tweet_id:1234567890123456789`  


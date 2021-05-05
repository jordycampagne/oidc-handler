<?php

class OIDCHandler {

    //In geval van opvragen van data van de IDP
    private $userDataSource = 'graph.microsoft.com/v1.0/me';
    private $redirectUrl;

    /**
     * Boots up and sets all needed data
     * @param string  $server (URL of server), without https. Example login.microsoftonline.com/oauth2/v2.0
     * @param string  $clientID
     * @param string  $clientSecret
     * @param string  $redirectUrl
     * @param boolean $test set to TRUE if you want to output the HEADER URL
     */
    function __construct(string $oath2Server, string $clientID, string $clientSecret, string $redirectUrl, bool $test = false)
    {
        $this->oath2Server = $server;
        $this->clientID = $clientID;
        $this->clientSecret = $clientSecret;

        $this->redirectUrl = $redirectUrl;
        $this->test = $test;
    }

    /**
     * Use this function to init the whole class.
     * Example:
     * $oauth = new OIDCHandler(.....);
     * $oauth->handle();
     *
     *
     * @return  [description]
     */
    function handle()
    {
        GLOBAL $_GET, $_SESSION;
        //Cancel is something isn't set
        if(empty($this->oath2Server) OR empty($this->clientID) OR empty($this->clientSecret)) {
            throw new Exception('Missing parameters.');
        }

        //Handle error (if present)
        if(!empty($_GET['error'])) {
            throw new Exception('Error: ' . $_GET['error']);
        }

        //Add some security (parse as utf-8)
        if(isset($_GET['state'])) {
            $_GET['state'] = htmlspecialchars($_GET['state'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        if(isset($_GET['code'])) {
            $_GET['code'] = htmlspecialchars($_GET['code'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }


        //The real work :-)
        if (empty($_GET['code'])) {
            //Step 1 -> authenticate
            return $this->authenticate();
        } elseif (session_id() == $_GET['state']) {
            //Step 2 -> Checking that the session_id matches to the state for security reasons AND authorize
            return $this->authorize($_GET['code']);
        }

    }

    /**
     * Build a redirect URL and redirect to that URL
     * @return redirect
     */
    private function authenticate()
    {
        $url = 'https://'.$this->oath2Server.'/authorize?state='.session_id().'&scope=openid&response_type=code&approval_prompt=auto';
        $url .= "&client_id=" . $this->clientID;
        $url .= "&redirect_uri=" . urlencode($this->redirectUrl);
        return $this->redirect($url);
    }

    /**
     * Handles all the data and flows needed to get the userData.
     * @param  string $code [description]
     * @return [type]       [description]
     */
    private function authorize(string $code)
    {
        //Get token
        $token = $this->getToken($code);
        //Get data
        $userData = $this->getUserData($token);

        return $userData;
    }

    /**
     * Redirects to a specified URL
     * @param  string $to full url
     * @return redirect
     */
    private function redirect(string $to)
    {
        return (($this->test === false) ? header('Location: '.$to) : $to);
    }

    /**
     * Get the Bearer token
     * @param  string $code [description]
     * @return string       [description]
     */
    private function getToken(string $code) : string
    {
        $content = 'grant_type=authorization_code';
        $content .= '&client_id='.$this->clientID;
        $content .= '&redirect_uri='.urlencode($this->redirectUrl);
        $content .= '&code='.$code;
        $content .= '&client_secret='.urlencode($this->clientSecret);

        $json = file_get_contents('https://'.$this->oath2Server.'/token', false, stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ".strlen($content)."\r\n",
                'content' => $content
            ]
        ]));

        $authdata = json_decode($json, true);
        if (isset($authdata['error'])) {
            throw new Exception('Error (getToken): '.$authdata['error']);
        }

        return $authdata['access_token'];
    }


    /**
     * Fetch data with the supplied Bearer token and returns it as a array.
     * TIP: do a print_r on the result.
     * @param  string $server URL of the data server (can be the same as oauth2 server)
     * @param  string $token  Bearer token
     * @return array          [description]
     */
    private function getData(string $server, string $token) : array
    {
        //Fetch
        $json = file_get_contents('https://'.$server, false, stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/json\r\nAuthorization: Bearer ".$token."\r\n"
            ]
        ]));

        $data = json_decode($json, true);
        if (isset($data['error'])) {
            throw new Exception('Error (getData): '.$data['error']);
        }

        return $data;
    }

}

?>

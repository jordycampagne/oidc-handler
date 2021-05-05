<?php
$test = 0;

require_once 'OIDCHandler.php';
if($test === 1 OR isset($_GET['state'])) {
    //Zet $test op 1 om alles te triggeren. Je kunt dit later verpakken in een IF--ELSE
    //die achter een button zit (tip: trigger dit via POST en geen GET).
    //Wel is het van belang dat het ook getriggerd wordt via een $_GET['state'].
    //de IDP verwijst terug naar de STATE in de URL.

    //--------------------------------------------------------------------------------------------------------//
    //Begin voorbeeld: een exection catchen:
    try {
    //Einde voorbeeld (haal weg indien je het niet wil gebruiken)
    //--------------------------------------------------------------------------------------------------------//

        //Het echte werk ;-);
        $OIDC = new OIDCHandler(
            env('oauth2')['tenantID'], //Tenant, kan waarschijnlijk weg
            env('oauth2')['clientID'], //clientID
            env('oauth2')['clientSecret'], //clientSecret
            BASE_URL, //Adres waarnaar OKTA terug moet linken
            false //Zet op true om te testen, dit toont de url waarnaar geredirect wordt.
        );

        $userData = $OIDC->handle();

    //--------------------------------------------------------------------------------------------------------//
    //Begin voorbeeld: een exection catchen:
    } catch (Exception $e) {
        //Met een code kun je dingen automatiseren. Iets met een IF eromheen bouwen bijvoorbeeld.
        //Geef de code dan wel mee bij het throwen van de exception. Voorbeeld:
        //throw new Exception('Fouttext', 101); (101 = code)
        exit('FATALE FOUT: '.$e->getMessage().'; CODE: '.$e->getCode());
    }
    //Einde voorbeeld (haal weg indien je het niet wil gebruiken)
    //--------------------------------------------------------------------------------------------------------//

    //Debug / test
    echo '<pre>';
    echo var_dump($userData);
    echo '</pre>';


    if(isset($userData['username'])) {
        echo 'GEBRUIKERSNAAM!';
        //we hebben een gebruikersnaam, dus we kunnen succesvol inloggen.

        /*
        Set de sessie voor de gebruiker, voorbeeld uit Neo4Z:
        $account->setSession($userData['username']);
        header("Location: index.php?padDitNogAan"); //Evt. aanpassen naar andere URL
        */

    }
}


?>

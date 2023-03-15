# SecureChatApp
Prototype of a secure chat-based messaging app, made for a cryptography school project


# Installation

``` 
python -m pip install -r requirements.txt
```

# Utilisation

`./server.py` : starts the server (port 80)
`./client.py` : starts the client (connects on http://127.0.0.1)

The server DB isn't saved (dict in memory), and therefore reset every time

# Objectifs :

Dans le fichier mycrypto.py se trouvent toutes les primitives crypto qui seront utiles
(AES, RSA, Hash) ... Normalement il y a tout :)

Il faut :
1 / changer le stockage des mots de passes, actuellement en clairs dans la "BDD"
2 / Chiffrer le canal entre client et serveur (attaquant 1)

Les endroits à changer sont les "#TODO" dans le code


# Petites infos techniques :

Le client va envoyer un JSON au serveur en POST
Ce JSON va contenir la clé AES chiffrée, l'IV, et le message chiffré en AES.

Ce message sera lui même du JSON :
côté client on donne à la fonction send_request un dict, et on le récupère dans la fonction handle_request du serveur.
Au milieu : il va falloir le chiffrer ....

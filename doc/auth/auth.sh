#!/bin/sh

# Authentification workflow, generate a JWT / CRSF token

cj --request POST \
  --url http://localhost:8080/auth \
  --header 'content-type: application/json' \
  --data '{
    "email": "machin@gmail.com",
    "password": "test"
}'

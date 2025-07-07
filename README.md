# Hybrid Cryptography using AES and RSA

## Project Description:
Hybrid Cryptography is one of the methodology to improve security by chaining mulitple or using combination of multiple cryptographic algorithms in security system.
This particular mode of hybrid cryptography uses AES and RSA for securing data. AES to encrypt data and RSA to encrypt the AES key.


> Read the `index.js` file thoroughly for better understanding.

# Implementation:
1. Download the completed ZIP file and extract.
2. Make sure you have latest version of NodeJS installed in your machine.
3. Install all the required dependencies using command `npm i`
4. Create a postgreSQL database, and add two tables namely,
   - admindata (with columns username and password)
   - patientdata (with columns patientid, patientname, encryptedhash and encryptediv)
5. Connect your database by configuring the .env file values `PG_DATABASE`, `PG_PASSWORD`.
6. Start the server by using `nodemon index.js`
7. Go to the address of `localhost://3000` in your browser.
8. Register admins and enter patient data.


# Common mistakes to avoid
- Make sure you dont specify any size on any columns of the table.
- If needed, conifgure the SQL queries in the `index.js` file.

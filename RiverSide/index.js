import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import forge from "node-forge";
import bcrypt from "bcrypt";
import { check, validationResult } from "express-validator";
import env from 'dotenv';


// const publickeyPem2 = `-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqpylPkho6E7whOR1rlv4
// 0SY+RU9Ci4IOkfkvvsVlu5BiOx2eQb0KDXrIvaiSaUP5tAVo5pn76tNYuBU9YjjU
// L7fcpFhOvV7AeUlW1psz5msCNJbvCvYrxdtouVXXyFDMjFGvzgGsS5WHf0ddL40g
// WnjxM748lQOcH+Jh93Ds9JH1sZKzLXdlufiUYy5vObUH6mhx2PL4xH3gOzbnYruj
// TNug8uykbHVyUEnn5NttYqoN21FmxiEVlLG3nH6PYFGL2yMiT/vWKHvSo9RXIm9v
// JmSYHhycEONwjJ+wpAOa8hlm5bsHtDwPwthHOFpdZJR4+yvhVIXaHowb0+9K3ATP
// cwIDAQAB
// -----END PUBLIC KEY-----`

// const privateKeyPem2 = `-----BEGIN RSA PRIVATE KEY-----
// MIIEogIBAAKCAQEAqpylPkho6E7whOR1rlv40SY+RU9Ci4IOkfkvvsVlu5BiOx2e
// Qb0KDXrIvaiSaUP5tAVo5pn76tNYuBU9YjjUL7fcpFhOvV7AeUlW1psz5msCNJbv
// CvYrxdtouVXXyFDMjFGvzgGsS5WHf0ddL40gWnjxM748lQOcH+Jh93Ds9JH1sZKz
// LXdlufiUYy5vObUH6mhx2PL4xH3gOzbnYrujTNug8uykbHVyUEnn5NttYqoN21Fm
// xiEVlLG3nH6PYFGL2yMiT/vWKHvSo9RXIm9vJmSYHhycEONwjJ+wpAOa8hlm5bsH
// tDwPwthHOFpdZJR4+yvhVIXaHowb0+9K3ATPcwIDAQABAoIBAEaQ7M3SgEWZpOSq
// Y7w+wS6sjTP4oPL305Pvx541oirOgLqnuPXCvR4vK0k6qHgOjAC3/hfnF6mcScU1
// z8JI9AZam1GETukHgD+KJHc2EWTb3Lkotm1HvXokEnAZv9rUBI6DGN5xlbRbgAQW
// XcYVroyNGmKG7CLML+6GIXQJSpCrAlcWf6vTEKdhnfL2hlsNMQbWn/cC35ncq9W+
// 0c0kxs5oKBYd+PP99nXX+Qq3t+tM8XLfyKRSXGDYKDxW9QTRMGsf8Ec4lzCKn5sm
// VogiWpikhwS9hCvHM5ERoB/Xn9BmkFVAIi74wdnNtJcYu8RgMDF8FScJDArGCsnk
// LaCgs4UCgYEA6QASNruX+zwtZnSy37lFezwmNx52aY5i/QgpXdQmHTUh869FLsiD
// sGqjKtVf4/NhgeV7trvOgHkMBtvgoLNHG/CRQN2KmyTrPp6JW4gPcMVW7v5ua4s4
// /eO5wHlNKATbIvl4jGOlrkWVe9pkbuk/W/PKGG6dmwJjdtZjKYw0tD8CgYEAu3QE
// SsPeuNdZyfRG5YJznoeurLRxm5crlUHKBST9/KT0ZEM0ebJxKkzVurdtRSJEWeOC
// vlogVSF/YkaO0XPxl4by4OcJiw1x99MgLNYH0MELGFKCSfPhlH28exseMAYJFSla
// z4cqiyblyxmIv4TxQRIz0+2FqFDQdCU/G4dtR80CgYAMayGNY0A9dr6guFWUUQag
// A9uxkmETTTB/dgDmbFk/s0ZE+7F/Rdam/3gE32yF9MHcr4OBgM8Hz+vRLcTyK7v9
// hDvpriUmEbisFL0TcNQJ2arBgDQYbUozVgDffleba27WlV9UdDcva6wE9uXld28W
// Eo9R8AtcaKsueUy9uShR9wKBgBqRqh4SvxnB5EccqYPURqD8qERwWv3rolDIf2LV
// SG6rzrv7To/FPAb71vtdDk7TOY7oEVr7mUOXuN9sEsgbP+3zQa+g75hW8oVm1lOk
// jn0HL5Rl9XOX7qxGWhW01UWHRXhLYUSy6tPIUp/D4b8Lj8piUxhBvUULF1CvCs/T
// FSktAoGATcSFi05Un/pKsd7a2OkgWfrK1i5ANvDZNTRIktnRjxe5Rm/q9rRT/Zdh
// HF9Hq7JnPrwFZSRF+2uPXwIR4K2yCCqW4nhxSILFzQXLk4IO8KFVQtajKzWIv//M
// WIv9xc0BXfwb6J9/egtlSQbkUEgRu9ST3tYagKQbrPmXCrn2X1I=
// -----END RSA PRIVATE KEY-----`



const app = express();
const port = 3000;
const saltRound  = 10;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
env.config();

const staticPrivateKey = forge.pki.privateKeyFromPem(process.env.PR_KEY);
const staticPubilcKey = forge.pki.publicKeyFromPem(process.env.PB_KEY)

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
  db.connect();


app.get("/", (req, res) => {
    // console.log("home page working");
    res.render("home.ejs");
});

app.get("/adminpage", (req, res) => {
    res.render("adminpage.ejs");
})


app.post("/login", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

     try{
        const result = await db.query("SELECT * FROM admindata WHERE username=$1", [email])

        if(result.rows.length > 0) {
            const user = result.rows[0];
            const passwordHash = user.password;
            bcrypt.compare(password, passwordHash, async (err, result) => {
                if(err) {
                    const alert = [ {
                        msg: "Server Error"
                    }]
                    res.render("home.ejs",{
                        alert
                    })
                    return;
                } else{
                    if(result) {
                        const successAlert = [{
                            msg: "Log in Successfull"
                        }]
                        res.render("adminpage.ejs", {
                            successAlert
                        });
                        return;
                    } else if(!result) {
                        const alert = [ {
                            msg: "Incorrect Password"
                        }]
                        res.render("home.ejs", {
                            alert
                        })
                        return;
                    }
                }
            })
            return;
        } else if(result.rows.length <= 0) {
            const alert = [ {
                msg: "Admin not found"
            }]
            res.render("home.ejs", 
                {
                    alert
                }
            )
            return;
        }
     }catch(err) {
        console.log(err)
     }
    res.render("adminpage.ejs")
})

app.post("/register",[
    check('email', 'Enter a valid email').exists().isEmail(),
    check('password', 'Set password between 8-16 characters').exists().isLength({min: 8, max: 16})
    ],  async (req, res) => {
        const email = req.body.email;
        const password = req.body.password;
        
        const errors = validationResult(req)
        if(!errors.isEmpty()) {
            const regAlert = errors.array();
            res.render("home.ejs", {
                regAlert
            })
            return;
        }

        try{
            const checkUserExists = await db.query("SELECT * from admindata WHERE username=$1", [email]);

            if(checkUserExists.rows.length > 0) {
                const regAlert = [
                    {
                        msg: "Admin already exists"
                    }
                ]
                res.render("home.ejs", {
                    regAlert
                })
                return;
            } else {
                bcrypt.hash(password, saltRound, async (err,hashValue) => {
                    const result = await db.query
                    ("INSERT INTO admindata (username, password) VALUES ($1, $2)", [email, hashValue]);
                    // console.log(hashValue);

                    const successAlert = [ {
                        msg: "Admin Registered Successfully!"
                    }]
                    res.render("adminpage.ejs", {
                        successAlert
                    })
                })
                return;
            }
        } catch(err) {
            console.log(err)
        }
})

app.post("/success", [
    check('mobileno', 'Enter a valid mobile number').exists().isLength({min: 10, max: 10}),
    check('aadhaar', 'Enter 12 Aadhaar characters').exists().isLength({min: 12, max: 12})
    
    ], async (req, res) => {

        const errors = validationResult(req)
        if(!errors.isEmpty()) {
            // return res.status(442).jsonp(errors.array())
            const alert = errors.array();
            console.log(alert)
            res.render("adminpage.ejs", {
                alert
            })
            return;
        }
            const name = req.body.username;
            const mobileno = req.body.mobileno;
            const aadhaar = req.body.aadhaar;
            const category = req.body.category;
            const gender = req.body.gender;
            const bloodgroup = req.body.bloodgroup;
        
            const obj = {
                username: name,
                mobileno: mobileno,
                aadhaar: aadhaar,
                category: category,
                gender:gender,
                bloodgroup:bloodgroup
        
            }
        
            const stringifiedObj = JSON.stringify(obj);
            // console.log("Stringified Object: ",stringifiedObj);
        
            var key = forge.random.getBytesSync(32);
            // console.log("This is the key",key)
            var iv = forge.random.getBytesSync(16);
            // console.log("This is the iv", iv)
        
        
            var cipher = forge.cipher.createCipher('AES-CBC', key);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(stringifiedObj));
            cipher.finish();
            var encrypted = cipher.output;
            const encryptedData = encrypted.data;
            const hexEncrypted = cipher.output.toHex();
        
            // outputs encrypted hex
            // console.log("Encrypted ",encrypted);
            console.log("Encrypted Data", encryptedData)
            console.log("Encrypted Hex", hexEncrypted)
        
            //Encrypt AES key with RSA
            const encryptedKey = staticPubilcKey.encrypt(key, 'RSA-OAEP');
            const encryptedKeyHex = forge.util.bytesToHex(encryptedKey);
            console.log("Encrypted  AES Key: ",encryptedKeyHex);
        
            //Encrypt Iv with base64
            const encryptedIv = forge.util.encode64(iv);
            console.log("Encrypted Iv: ", encryptedIv);
            try{
                const result = await db.query(
                    "INSERT INTO patientdata (patientname, encryptedHash, encryptedKey, encryptedIv) VALUES ($1, $2, $3, $4) RETURNING*", [name, hexEncrypted, encryptedKeyHex, encryptedIv]
                )
                res.render("success.ejs");
                return;
                // console.log(result.rows[0].encryptedhash);
                // console.log("Query Result", result.rows[0].userdata);
                // console.log("Query Result", result.rows[0].encryptedhash);
            } catch (err){
                console.log(err);
            }
            // console.log("Original Data: ",data);
})

app.get("/getdata", async(req, res) => {

    try{
        const result = await db.query("SELECT * FROM patientdata ORDER BY patientid DESC LIMIT 1");  
        // console.log("Fetched rows from database: ",result);
        const dbhex = result.rows[0].encryptedhash;
        const dbkey = result.rows[0].encryptedkey;
        const dbiv = result.rows[0].encryptediv;
        const patientId = result.rows[0].patientid;

        // console.log("dbhex: ", dbhex);
        // console.log("dbKey: ", dbkey);
        // console.log("dbIv: ", dbiv);
        // console.log("patient id", patientId);

        //Decrypt AES key with RSA
        const decryptedKeyBytes = forge.util.hexToBytes(dbkey)
        const decryptedKey = staticPrivateKey.decrypt(decryptedKeyBytes, 'RSA-OAEP');
        console.log("Decrypted Key: ", decryptedKey)

        //Decrypt Iv with base64
        const decryptedIv = forge.util.decode64(dbiv);
        console.log("Decrypted Iv: ", decryptedIv)

        const encryptedBuffer = forge.util.createBuffer(forge.util.hexToBytes(dbhex));
        // console.log("Encrypted Buffer", encryptedBuffer)
        var decipher = forge.cipher.createDecipher('AES-CBC', decryptedKey);
        decipher.start({iv: decryptedIv});
        decipher.update(encryptedBuffer);
        var decryptedResult = decipher.finish(); 
        // check 'result' for true/false

        // outputs decrypted hex
        // console.log("Decrypted", decipher.output);
        const string = decipher.output.data;
        const stringToObj = JSON.parse(string);
        // console.log("String to object converted:",stringToObj);
        // console.log("Decrypted hex",decipher.output.data);  

        console.log("Decrypted username",stringToObj.username);  
        console.log("Decrypted mobile",stringToObj.mobileno);  
        console.log("Decrypted aadhaar",stringToObj.aadhaar);
        console.log("Decrypted Category",stringToObj.category)
        console.log("Decrypted gender", stringToObj.gender)
        console.log("Decrypted Blood Group",stringToObj.bloodgroup)

        res.render("patientdata.ejs", {
            patientData: stringToObj
        })
    } catch(err){
        console.log(err);
    }
})


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
  
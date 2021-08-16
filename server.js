const express = require("express");
const app = express();
const port = 3987;

// Server URL
const ENV = process.env.NODE_ENV; // 'production'/'development'
const serverRootUrl =
  ENV === "production" ? "http://yarrumevets.com" : "http://localhost";

// For sending verification email
var nodemailer = require("nodemailer");

// DB stuff.
var mongodb = require("mongodb");
var MongoClient = mongodb.MongoClient;
var mongoURL = "mongodb://localhost:27017";
var db;

// Encryption stuff.
const secret = require("../secret.config.js");
const jwt = require("jwt-simple");
let tokenSecret;
const crypto = require("crypto");
const passwordSecret = secret.passwordSecret;

// passport-http-bearer stuff
const BearerStrategy = require("passport-http-bearer").Strategy;

const bodyParser = require("body-parser");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

//----------------------------------------------------------------------//

// For IP forwarding. (also add to nginx: proxy_set_header X-Real-IP $remote_addr;, inside http {}) although I did not use it.
app.set("trust proxy", true);

app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log(new Date().toISOString(), " - ", req.query, " url: ", req.url);
  // Create a secret key with the user's IP. Will have to login again from another location.
  tokenSecret = secret.tokenSecret + req.ip; // @TODO: test/fix this.
  next();
});

// Authenticate with a username/password and receive a token.
// jwt-simple
passport.use(
  new LocalStrategy((username, password, done) => {
    const hash = crypto
      .createHmac("sha256", passwordSecret)
      .update(password)
      .digest("hex");
    console.log("Attemped PW Hash: ", hash);

    db.collection("users").findOne({ username: username }, (err, user) => {
      console.log("user: ", user);
      console.log("Database PW Hash: ", user.password);
      if (user && user.password && user.password === hash) {
        if (user.status !== "verified") {
          done("Account email not verified.", false);
          return;
        }

        // Got authorized! Return token.
        done(null, jwt.encode({ username }, tokenSecret));
        return;
      }
      // Didn't get authorized :(
      done("Username or password incorrect.", false);
    }); // ...db.
  })
);

// Authenticate with a token to access private routes.
// Bearer strategy.
passport.use(
  new BearerStrategy((token, done) => {
    console.log("bearer strategy.");
    try {
      const { username } = jwt.decode(token, tokenSecret);
      console.log("Username from TOKEN: ", username);
      db.collection("users").findOne({ username: username }, (err, user) => {
        if (user && user.username) {
          console.log("DB USER: ", user);
          console.log("err: ", err);
          // some data exists. @TODO - clean this up.
          done(null, username);
          return;
        }
        // Username from token not found in db.
        done(null, false);
      }); // ...db.
    } catch (error) {
      console.log("Oopsie!");
      done(null, false);
    }
  })
);

// Do login.
app.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    console.log("/login");
    res.send({
      token: req.user,
    });
  }
);

app.post("/check", (req, res) => {
  // @TODO Redundant code - move this into function used by /check and /signup.
  // check db for existing user or email
  const { username, email } = req.body;
  console.log("user: ", username, " email: ", email);
  db.collection("users").findOne(
    { $or: [{ username: username }, { email: email }] },
    (err, results) => {
      console.log("RESULTS: ", results);
      console.log("ERR: ", err);
      if (results) {
        res.status(500);
        res.send("Username or email already taken x");
        return;
      }
      res.status(200);
      res.send("Username and email available √");
    }
  ); // ...db.
});

// Verify email with hash.
app.get("/api/verify/:hash", (req, res) => {
  console.log("req params: ", req.params);
  // get hash from req params.
  const verifyHash = req.params["hash"];
  console.log("verify this hash: ", verifyHash);
  // fetch user by hash
  // check db for existing user or email
  db.collection("users").findOne(
    { verifyEmailHash: verifyHash },
    (err, results) => {
      console.log("results: ", results, " err: ", err);

      if (!err && results) {
        // set account status to "verified"
        db.collection("users").updateOne(
          { verifyEmailHash: verifyHash },
          {
            $set: { status: "verified" },
          },
          (err, result) => {
            console.log("Account verified!");
            res.send("account verified!");
            return;
          }
        );
      } else {
        res.status(404);
        res.send("Hash not found.");
      }
    } // ..findOne callback.
  );
});

// Do signup
app.post("/signup", (req, res) => {
  // Get user entered data.
  const { username, password, email, firstName, lastName } = req.body;
  // Validation.
  const nameRegex = /^([a-zA-Z]){1,16}$/; // 2 to 16 letters.
  const usernameRegex = /^[a-zA-Z]([a-zA-Z0-9]){3,16}$/; // 4 to 16 letters or numbers, first must be a letter.
  const passwordRegex = /^([a-zA-Z0-9!@#$%&*~?\-.=_+^]){8,32}$/; // 8 to 32 characters
  const emailRegex = /[a-zA-Z0-9_\.\+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-\.]+/;
  let errors = [];
  if (!usernameRegex.test(username)) errors.push("username");
  if (!nameRegex.test(firstName)) errors.push("firstName");
  if (!nameRegex.test(lastName)) errors.push("lastName");
  if (!emailRegex.test(email)) errors.push("email");
  if (!passwordRegex.test(password)) errors.push("password");
  if (errors.length) {
    res.status(500);
    res.send("Error sending confirmation email.");
    401;
    res.send(errors);
    return;
  }

  // check db for existing user or email
  db.collection("users").findOne(
    { $or: [{ username: username }, { email: email }] },
    (err, results) => {
      console.log("<> RESULTS: ", results);
      if (results) {
        res.status(500);
        res.send("Error sending confirmation email.");
        400;
        res.send("Username or email already taken.");
        return;
      }
      // Hash the password.
      const passwordHash = crypto
        .createHmac("sha256", passwordSecret)
        .update(password)
        .digest("hex");
      // Create email verification hash.
      var current_date = new Date().valueOf().toString();
      var random = Math.random().toString();
      const verifyEmailHash = crypto
        .createHash("sha1")
        .update(current_date + random)
        .digest("hex");
      // Add user to database.
      db.collection("users").insert(
        {
          username,
          firstName,
          lastName,
          password: passwordHash,
          verifyEmailHash,
          status: "pending",
          email,
        },
        (err, result) => {
          console.log("err: ", err);
          console.log("result: ", result);
          const userFromDb = result.ops[0];
          console.log("user from db: ", userFromDb);
          console.log("err: ", err);

          sendVerificationEmail(res, verifyEmailHash, email, firstName);
        }
      );
    }
  ); // ...db.
});

const sendVerificationEmail = (res, hash, userEmail, userFirstName) => {
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: secret.gmailAccount,
      pass: secret.gmailPassword,
    },
  });
  var mailOptions = {
    from: secret.gmailAccount,
    to: userEmail,
    subject: "yarrumevets.com | verify email address for sign-up",
    html: `<h2>yarrumevets.com account verification</h2><p>${userFirstName}, you need to veryify your email address by clicking the link below:</p><p><a href='${serverRootUrl}/auth/api/verify/${hash}'>${serverRootUrl}/auth/api/verify/${hash}</a></p>`,
  };

  console.log("sending email... ", mailOptions);

  // Send the confirmation email.
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
      res.status(500);
      console.error("Error sending confirmation email: ", error);
      res.send("Error sending confirmation email.");
      return;
    } else {
      res.status(200);
      res.send("Email sent!");
    }
  });
};

//-------------- RESET PASSWORD ---------------------//

// Send reset password email
app.post("/resetpasswordrequest", (req, res) => {
  const { email } = req.body;

  // check db for existing user or email
  db.collection("users").findOne({ email: email }, (err, results) => {
    console.log("results: ", results, err);
    if (results.email) {
      sendPasswordResetEmail(results.email, res);
      res.send("OK");
      return;
    } else {
      res.status(404);
      res.send("Email not found. Or some other error.");
    }
  }); // ..db find user by email.
});
const sendPasswordResetEmail = (email, res) => {
  var current_date = new Date().valueOf().toString();
  var random = Math.random().toString();
  const hash = crypto
    .createHash("sha1")
    .update(current_date + random)
    .digest("hex");
  db.collection("users").updateOne(
    { email },
    {
      $set: { resetPasswordHash: hash },
    },
    (err, result) => {
      console.log("verify hash updated! Result: ", result, " err: ", err);

      // send the email.
      var transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: secret.gmailAccount,
          pass: secret.gmailPassword,
        },
      });
      var mailOptions = {
        from: secret.gmailAccount,
        to: email,
        subject: "yarrumevets.com | reset password",
        html: `<h2>yarrumevets.com password reset</h2><p>There was a reset password request for this email address.</p>Click the link below to reset your password.<p></p><p><a href='${serverRootUrl}/auth/resetpassword.html?hash=${hash}'>${serverRootUrl}/auth/resetpassword.html?hash=${hash}</a></p>`,
      };
      // Send the reset email.
      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
          res.status(500);
          console.error("Error sending reset email: ", error);
          res.send("Error sending reset email.");
          return;
        } else {
          res.status(200);
          res.send("Email sent!!!!!");
        }
      });
    }
  );
};

// Send reset password email
app.post("/api/resetpassword", (req, res) => {
  const { hash, password } = req.body;
  // Hash the new password
  const passwordHash = crypto
    .createHmac("sha256", passwordSecret)
    .update(password)
    .digest("hex");
  db.collection("users").findOne(
    { resetPasswordHash: hash },
    (err, results) => {
      console.log("results: ", results, " err: ", err);
      // If results return a user. Arbitrary test.
      if (results && results.resetPasswordHash === hash) {
        db.collection("users").updateOne(
          { resetPasswordHash: hash },
          {
            $set: { password: passwordHash },
          },
          (err, result) => {
            // @TODO - remove the reset password hash.

            console.log("Password Updated");
            res.send("Password Updated");
            return;
          }
        );
      } // ..if user found.
      else {
        res.status(404);
        res.send("Invalid hash.");
      }
    }
  ); // ..find user by hash.
});

// --------------------------- end of reset password ----------------------------- //

// Public folder.
app.use("/", express.static(__dirname + "/public"));

// Private folder.
app.use(
  "/private",
  passport.authenticate("bearer", { session: false }),
  express.static(__dirname + "/private")
);

// Start server and db.
MongoClient.connect(mongoURL, { useNewUrlParser: true }, (err, client) => {
  if (err) {
    console.log("Unable to connect to the mongoDB server. Error:", err);
  } else {
    db = client.db("yarrumevets");
    console.log("Connected to db...");
    app.listen(port, function () {
      console.log(
        "Passport.js auth test server listening on port " + port + "..."
      );
    });
  }
});

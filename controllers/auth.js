const User = require("../models/user");
const jwt = require("jsonwebtoken");
const expressJwt = require("express-jwt");
const axios = require("axios");
const _ = require("lodash");
const { OAuth2Client } = require("google-auth-library");
const fetch = require("node-fetch");
// sendgrid
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// exports.signup = (req, res) => {
//   //console.log("REQ BODY IN SIGNUP", req.body);
//   const { name, email, password } = req.body;

//   User.findOne({ email }).exec((err, user) => {
//     if (user) {
//       return res.status(400).json({
//         error: "Email is taken",
//       });
//     }
//   });

//   let newUser = new User({ name, email, password });

//   newUser.save((err, success) => {
//     if (err) {
//       console.log("SIGNUP ERROR", err);
//       return res.status(400).json({
//         error: err,
//       });
//     }
//     res.json({
//       message: "Signup success! Please sign in.",
//     });
//   });
// };

exports.signup = (req, res) => {
  const { name, email, password } = req.body;

  User.findOne({ email }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: "Email is taken",
      });
    }

    const token = jwt.sign(
      { name, email, password },
      process.env.JWT_ACCOUNT_ACTIVATION,
      { expiresIn: "10m" }
    );

    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "Account activation link",
      html: `
        <h1>Please use the following link to activate your account</h1>
        <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
        <hr/>
        <p>Your link is active for 10 minutes. After that, you will need to resend the verification email.</p>
        <p>${process.env.CLIENT_URL}</p>
        `,
    };

    sgMail
      .send(emailData)
      .then((sent) => {
        //console.log("SIGNUP EMAIL SENT", sent);
        return res.json({
          message: `Email has been sent to ${email}. Follow the instructions to activate your account.`,
        });
      })
      .catch((err) => {
        // console.log('SIGNUP EMAIL SENT ERROR', err)
        return res.json({
          message: err.message,
        });
      });
  });
};

exports.accountActivation = (req, res) => {
  const { token } = req.body;

  if (token) {
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function (
      err,
      decoded
    ) {
      if (err) {
        console.log("JWT VERIFY IN ACCOUNT ACTIVATION ERROR", err);
        return res.status(401).json({
          error: "Expired link. Signup again",
        });
      }

      const { name, email, password } = jwt.decode(token);

      const user = new User({ name, email, password });

      user.save((err, user) => {
        if (err) {
          console.log("SAVE USER IN ACCOUNT ACTIVATION ERROR", err);
          return res.status(401).json({
            error: "Error saving user in database. Try signup again",
          });
        }
        return res.json({
          message: "Signup success. Please signin.",
        });
      });
    });
  } else {
    return res.json({
      message: "Something went wrong. Try again.",
    });
  }
};

exports.signin = (req, res) => {
  const { email, password } = req.body;
  // check if user exist
  User.findOne({ email }).exec((err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User with that email does not exist. Please sign up.",
      });
    }
    // authenticate
    if (!user.authenticate(password)) {
      return res.status(400).json({
        error: "Email and password do not match.",
      });
    }
    // generate token and send to client
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d", // token expiration time
    });
    const { _id, name, email, role } = user;

    return res.json({
      token,
      user: { _id, name, email, role },
    });
  });
};

exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET, // can access req.user._id & req.user.expiresIn
  algorithms: ["HS256"],
});

exports.adminMiddleware = (req, res, next) => {
  User.findById({ _id: req.user._id }).exec((err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User not found.",
      });
    }

    if (user.role !== "admin") {
      return res.status(400).json({
        error: "Admin resources. Access denied",
      });
    }

    req.profile = user;
    next();
  });
};

exports.forgotPassword = (req, res) => {
  const { email } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User with that email does not exist",
      });
    }

    const token = jwt.sign(
      { _id: user._id, name: user.name },
      process.env.JWT_RESET_PASSWORD,
      {
        expiresIn: "10m",
      }
    );

    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "Password Reset link",
      html: `
            <h1>Please use the following link to reset your password.</h1>
            <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
            <hr/>
            <p>Your link is active for 10 minutes. After that, you will need to resend the verification email.</p>
            <p>${process.env.CLIENT_URL}</p>
            `,
    };

    return user.updateOne({ resetPasswordLink: token }, (err, success) => {
      if (err) {
        console.log("RESET PASSWORD LINK ERROR", err);
        return res.status(400).json({
          error: "Database connection error on user password forgot request",
        });
      } else {
        sgMail
          .send(emailData)
          .then((sent) => {
            //console.log("SIGNUP EMAIL SENT", sent);
            return res.json({
              message: `Email has been sent to ${email}. Follow the instructions to activate your account.`,
            });
          })
          .catch((err) => {
            // console.log('SIGNUP EMAIL SENT ERROR', err)
            return res.json({
              message: err.message,
            });
          });
      }
    });
  });
};

exports.resetPassword = (req, res) => {
  const { resetPasswordLink, newPassword } = req.body;

  console.log("newPassword ", newPassword);

  if (resetPasswordLink) {
    jwt.verify(
      resetPasswordLink,
      process.env.JWT_RESET_PASSWORD,
      (err, decoded) => {
        if (err) {
          return res.status(400).json({
            error: "Expired link. Try again.",
          });
        }
        User.findOne({ resetPasswordLink }, (err, user) => {
          if (err || !user) {
            return res.status(400).json({
              error: "Something went wrong. Try later.",
            });
          }
          const updatedFields = {
            password: newPassword,
            resetPasswordLink: "",
          };

          user = _.extend(user, updatedFields); // updates changed information
          user.save((err, results) => {
            if (err) {
              return res.status(400).json({
                error: "Error resetting user password",
              });
            }
            res.json({
              message: `Great! Now you can login with your new password.`,
            });
          });
        });
      }
    );
  }
};

// Google

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
exports.googleLogin = (req, res) => {
  const { idToken } = req.body;

  client
    .verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
    .then((response) => {
      console.log("GOOGLE LOGIN RESPONSE", response);
      const { email_verified, name, email } = response.payload;
      if (email_verified) {
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: "7d",
            });
            const { _id, email, name, role } = user;
            return res.json({ token, user: { _id, email, name, role } });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log("ERROR GOOGLE LOGIN ON USER SAVE", err);
                return res
                  .status(400)
                  .json({ error: "User signup failed with Google" });
              }
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                {
                  expiresIn: "7d",
                }
              );
              const { _id, email, name, role } = data;
              return res.json({ token, user: { _id, email, name, role } });
            });
          }
        });
      } else {
        return res
          .status(400)
          .json({ error: "Google login failed. Try again." });
      }
    });
};

// FACEBOOK

exports.facebookLogin = (req, res) => {
  console.log("FACEBOOK LOGIN REQUEST BODY", req.body);
  const { userID, accessToken } = req.body;

  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;

  return (
    fetch(url, {
      method: "GET",
    })
      .then((response) => response.json())
      // .then(response => console.log(response))
      .then((response) => {
        const { email, name } = response;
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: "7d",
            });
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role },
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log("ERROR FACEBOOK LOGIN ON USER SAVE", err);
                return res.status(400).json({
                  error: "User signup failed with facebook",
                });
              }
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                { expiresIn: "7d" }
              );
              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role },
              });
            });
          }
        });
      })
      .catch((error) => {
        res.json({
          error: "Facebook login failed. Try later",
        });
      })
  );
};

// LINKEDIN

exports.linkedinLogin = (req, res) => {
  // Get code and state needed to get access token
  //console.log("req.query.code ", req.query.code); // code
  //console.log("req.query.state ", req.query.state); // state
  const code = req.query.code;
  const user = {
    firstName: "",
    lastName: "",
    email: "",
  };

  const requestUserData = async () => {
    const getAccessToken = await axios({
      method: "POST",
      url: `https://www.linkedin.com/oauth/v2/accessToken?grant_type=authorization_code&code=${code}&redirect_uri=${process.env.LINKEDIN_REDIRECT_URI}&client_id=${process.env.LINKEDIN_CLIENT_ID}&client_secret=${process.env.LINKEDIN_CLIENT_SECRET}`,
    })
      .then((response) => {
        console.log("LINKEDIN ACCESS TOKEN SUCCESS", response.status);
        return response.data.access_token;
        //return res.json({ access_token: response.data.access_token });
      })
      .catch((error) => {
        console.log("LINKEDIN ACCESS TOKEN ERROR", error);

        return res.json(error);
      });

    const access_token = getAccessToken;
    //console.log("access_token ", access_token);

    const getNames = await axios({
      method: "GET",
      url: "https://api.linkedin.com/v2/me",
      headers: { Authorization: `Bearer ${access_token}` },
    })
      .then((response) => {
        console.log(
          "LINKEDIN PROFILE SUCCESS",
          response.status,
          response.statusText
        );
        // console.log(response.data);
        return {
          firstName: response.data.localizedFirstName,
          lastName: response.data.localizedLastName,
        };
      })
      .catch((error) => {
        console.log("LINKEDIN PROFILE ERROR", error);

        return res.json({
          error: error.response.status + error.response.statusText,
        });
      });

    const names = getNames;
    //console.log("names ", names);
    user.firstName = names.firstName;
    user.lastName = names.lastName;
    const name = user.firstName + " " + user.lastName;

    const getEmail = await axios({
      method: "GET",
      url: `https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))&oauth2_access_token=${access_token}`,
    })
      .then((response) => {
        console.log("LINKEDIN ACCESS EMAIL SUCCESS", response.status);
        // console.log(
        //   "response.data.elements[0] ",
        //   response.data.elements[0]["handle~"].emailAddress
        // );
        const emailAddress = response.data.elements[0]["handle~"].emailAddress;
        //console.log(emailAddress);
        return emailAddress;
      })
      .catch((error) => {
        console.log("LINKEDIN ACCESS EMAIL ERROR", error);

        return res.json(error);
      });

    const email = getEmail;
    //console.log("email ", email);
    user.email = email;

    User.findOne({ email }).exec((err, user) => {
      if (user) {
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });
        const { _id, email, name, role } = user;
        //console.log({ _id, email, name, role });
        res.render("callback", {
          data: {
            token,
            user: { _id, email, name, role },
          },
        });
      } else {
        let password = email + process.env.JWT_SECRET;
        user = new User({ name, email, password });
        user.save((err, data) => {
          if (err) {
            console.log("ERROR LINKEDIN LOGIN ON USER SAVE", err);
            return res.status(400).json({
              error: "User signup failed with LinkedIn",
            });
          }
          const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
          });
          const { _id, email, name, role } = data;
          res.render("callback", {
            data: {
              token,
              user: { _id, email, name, role },
            },
          });
        });
      }
    });
  };

  requestUserData();
};

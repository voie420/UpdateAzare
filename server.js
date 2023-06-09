const express = require('express');
const cookieParser = require('cookie-parser');
const mysql = require('mysql2');
const fs = require('fs');
const ejs = require('ejs');
const session = require('express-session')
const sharp = require('sharp');
const bodyParser = require('body-parser');
const multer = require('multer');
const ffmpegPath = require('@ffmpeg-installer/ffmpeg').path;
const ffmpeg = require('fluent-ffmpeg');
const upload = multer({ dest: 'uploads/' });
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

const debugging = true

app.use(
  session({
    secret: '0adfbs56bzc358b465767890z+b8d6fbe5zcxzcv890dgh54y24wet356zb789cn7890578rg4wer7f8',
    resave: false,
    saveUninitialized: false
  })
);

const dbConfig = {
  host: "localhost",
  user: "root",
  password: "",
  database: "application",
  port: 3306,
  //ssl: { ca: fs.readFileSync('./DigiCertGlobalRootCA.crt.pem') }
};

app.get('/', (req, res) => {
  res.render('index');
});


app.get('/Upload', (req, res) => {
  res.render('upload')
})

const { spawn } = require('child_process');

// Set the ffmpeg path
ffmpeg.setFfmpegPath(ffmpegPath);

// Set the destination and filename for uploaded videos
const storage = multer.diskStorage({
  destination: './UserUploaded/videos',
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

// Create multer upload instance
const uploadPath = multer({ storage: storage });

app.post("/upload", upload.single("videoFile"), function(req, res) {
  if (req.session.ACCESS_TOKEN) {
    const connection = mysql.createConnection(dbConfig);

    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });

    connection.query('SELECT * FROM user_data', async (error, results, fields) => {
      let LoggedInId;
      await Promise.all(results.map(async (Result) => {
        const VALID = await bcrypt.compare(Result.USR_ACS_TOKEN, req.session.ACCESS_TOKEN);
        if (VALID) {
          LoggedInId = Result.USR_ID;
        }
      }));

      if (LoggedInId) {
        // Get the uploaded file
        const videoFile = req.file;
      
        // Check if file exists
        if (!videoFile) {
          console.error("No file uploaded");
          return res.status(400).send("No file uploaded");
        }
      
        // Create a unique filename for the resized video
        const resizedFileName = "resized_" + Date.now() + ".mp4";
      
        // Resize the video using FFMPEG
        try {
          ServerLog("Started uploading video. Might take a little while!")
          ffmpeg(videoFile.path)
          .size("1080x1920")
          .save(path.join(__dirname, "public", "UserUploaded", "videos", resizedFileName))
          .on("end", () => {
            console.log("Finished!")
            connection.query(`INSERT INTO videos (FILE_NAME, OWNER_ID) VALUES ('${resizedFileName}', '${LoggedInId}')`, async (error, results, fields) => {
              if (error) {
                res.status(403)
              }
            })

          })
          .on("error", (err) => {
            console.error("Error resizing video: " + err.message);
            return res.status(500).send("Failed to resize video");
          });
        } catch (err) {
          console.error("Error resizing video: " + err.message);
          return res.status(500).send("Failed to resize video");
        }
      } else {
        res.redirect("/home")
      }
    })}
});



async function generateFileName() {
  let fileName;
  let filePath = path.join(__dirname, 'public', 'UserUploaded', 'images');
  let files = await fs.promises.readdir(filePath);

  do {
    fileName = crypto.randomBytes(20).toString('hex');
  } while (files.includes(fileName));

  return fileName;
}

async function Hash(password) {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

function ServerLog(message) {
  console.log(`[ SERVER: ${message} ]`)
}

app.get('/login', function(req, res) {
  // some login logic here...
  res.redirect('/home?action=login');
});

app.get('/followers', (req, res) => {
  res.render('followers')
})

app.get('/following', (req, res) => {
  res.render('following')
})

app.get('/signup', function(req, res) {
  // some login logic here...
  res.redirect('/home?action=signup');
});

app.get('/home', function(req, res) {
  res.render('index');
});

async function generateAccessToken() {
  const connection = mysql.createConnection(dbConfig);

  try {
    let accessToken;
    let foundToken = false

    while (foundToken == false) {
      accessToken = crypto.randomBytes(30).toString("hex");
  
      const query = 'SELECT * FROM user_data';
  
      connection.query(query, function (error, results, fields) {
        connection.end();
        if (error) {
          console.error(error);
          throw error;
        }
        
        results.forEach(function(user) {
          if (accessToken == user.USR_ACS_TOKEN) {
            foundToken = true
          }
        });
      });
  
      // close the database connection
      if (foundToken == false) {
        return accessToken;
      }
    }

  } catch (error) {
    console.error("Error generating access token:", error);
    throw error;
  }
}





const fileUpload = require('express-fileupload');
const { stringify } = require('querystring');
const { createConnection } = require('net');
app.use(fileUpload());

app.post('/SaveProfileImage', (req, res) => {
  const processedImage = req.files.image;
  const ACCESS_TOKEN = req.session.ACCESS_TOKEN
  const ID = req.body.id
  const MultiAction = req.body.MultiAction

  if (!processedImage) {
    res.status(400).json({ error: 'No image uploaded' });
  } else {
    const fileName = generateFileName().then(GivenName => {
      const filePath = path.join('./public/UserUploaded/images', `${GivenName}.png`);

      processedImage.mv(filePath, (err) => {
        if (err) {
          console.error(err);
          res.status(500).json({ error: 'Failed to save image' });
        } else {
          const connection = mysql.createConnection(dbConfig);

          connection.connect((error) => {
            if (error) {
              console.error('Error connecting to MySQL:', error);
              return;
            }
          });

          connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [ID], (error, results, fields) => {
            bcrypt.compare(results[0].USR_ACS_TOKEN, ACCESS_TOKEN).then(VALID => {
              if (VALID) {
                connection.query(`UPDATE user_data SET USR_IMAGE = '${GivenName}.png' WHERE USR_ID = ${ID};`)
                connection.end();
                if (MultiAction) {
                  return res.status(200).send({ err:false ,message: "All changes has been saved."})
                } else {
                  return res.status(200).send({ err:false ,message: "Status has been updated."})
                }
              } else {
                return res.status(403).send("Not authorized.")
              }
            })
          })

        }
      });

    })
  }
});

app.post('/Fetch/FrontpageUsers', (req, res) => {
  if (req.session.ACCESS_TOKEN) {
    const connection = mysql.createConnection(dbConfig);

    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });

    connection.query('SELECT * FROM user_data', async (error, results, fields) => {
      let LoggedInId;
      await Promise.all(results.map(async (Result) => {
        const VALID = await bcrypt.compare(Result.USR_ACS_TOKEN, req.session.ACCESS_TOKEN);
        if (VALID) {
          LoggedInId = Result.USR_ID;
        }
      }));

      if (LoggedInId) {
        connection.query(`SELECT USR_ID, USR_USERNAME, USR_APPROVED, USR_IMAGE FROM user_data WHERE USR_ID != ${LoggedInId} ORDER BY RAND() LIMIT 5`, (error, Users, fields) => {
          if (error) {
            console.error('Error fetching user data:', error);
            res.status(500).send({ success: false, error: 'Failed to fetch user data' });
          } else {
            // Check if any users were fetched
            if (Users.length !== 0) {
              res.status(200).send({ success: true, fetchedUsers: Users });
            } else {
              console.log('No users found');
              res.status(200).send({ success: false });
            }
          }
        });
      } else {
        console.error('LoggedInId is undefined');
        res.status(400).send({ success: false, error: 'Invalid request' });
      }

      connection.end();
    });
  } else {

    const connection = mysql.createConnection(dbConfig);
    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });

    connection.query(`SELECT USR_ID, USR_USERNAME, USR_APPROVED, USR_IMAGE FROM user_data ORDER BY RAND() LIMIT 5`, (error, Users, fields) => {
      res.status(200).send({ success: true, fetchedUsers: Users });
    })
  }
});


app.post('/Session/Remove', (req, res) => {
  if (req.session.ACCESS_TOKEN) {
    res.clearCookie('ACCESS_TOKEN');
    res.status(200).send({err:false, message: "Logged out."})
  } else {
    res.status(200).send({err:true, message: "You are not signed into any account.  "})
  }
})

app.get('/fetchFollowers', (req, res) => {
  const Target = req.query.id

  if (Target) {
    const connection = mysql.createConnection(dbConfig);

    let hasFollowers = false

    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }

      connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [Target], (error, viewingUser, fields) => {
        connection.query('SELECT * FROM following WHERE FOLLOWED = ?', [Target], (error, results, fields) => {
          let userData = [];
          let i = 0

          if (results.length != 0) {
            results.forEach((row) => {
              connection.query('SELECT USR_ID, USR_USERNAME, USR_IMAGE, USR_APPROVED FROM user_data WHERE USR_ID = ?', [row.FOLLOWED_BY], (error, user, fields) => {
                if (error) {
                  console.error(error);
                  return;
                }

                // If a matching user was found, add their data to the userData array
                if (user.length > 0) {
                  userData.push(user[0]);
                }

                if (++i === results.length) {
                  connection.end(); // Close the connection after all queries are executed
                  res.status(200).send({hasFol: true ,viewingUsername: viewingUser[0].USR_USERNAME, viewingID: viewingUser[0].USR_ID, approved: viewingUser[0].USR_APPROVED, Followersdata: userData})
                }
              });
            });
          } else {
            connection.end(); // Close the connection when there are no results
            res.status(200).send({hasFol: false ,viewingUsername: viewingUser[0].USR_USERNAME, viewingID: viewingUser[0].USR_ID, approved: viewingUser[0].USR_APPROVED, Followersdata: userData})
          }
        })
      })
    });
  }
});





app.get('/fetchFollowing', (req, res) => {
  const Target = req.query.id
  const ACCESS_TOKEN = req.session.ACCESS_TOKEN

  if (Target) {
    const connection = mysql.createConnection(dbConfig);

    let hasFollowing = false

    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [Target], (error, results, fields) => {
      bcrypt.compare(results[0].USR_ACS_TOKEN, ACCESS_TOKEN).then(IsOwner => {
        connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [Target], (error, viewingUser, fields) => {
          connection.query('SELECT * FROM following WHERE FOLLOWED_BY = ?', [Target], (error, results, fields) => {
            let userData = [];
            let i = 0
    
            if (results.length != 0) {
              results.forEach((row) => {
                connection.query('SELECT USR_ID, USR_USERNAME, USR_IMAGE, USR_APPROVED FROM user_data WHERE USR_ID = ?', [row.FOLLOWED], (error, user, fields) => {
                  if (error) {
                    console.error(error);
                    connection.end(); // Close the connection in case of error
                    return;
                  }
                  
                  // If a matching user was found, add their data to the userData array
                  if (user.length > 0) {
                    userData.push(user[0]);
                  }
      
                  if (++i === results.length) {
                    res.status(200).send({hasFol: true , Own: IsOwner ,viewingUsername: viewingUser[0].USR_USERNAME, viewingID: viewingUser[0].USR_ID, approved: viewingUser[0].USR_APPROVED, Followingdata: userData})
                    connection.end(); // Close the connection after all queries are executed
                  }
                });
              });
            } else {
              res.status(200).send({hasFol: false, Own: IsOwner  ,viewingUsername: viewingUser[0].USR_USERNAME, viewingID: viewingUser[0].USR_ID, approved: viewingUser[0].USR_APPROVED, Followingdata: userData})
              connection.end(); // Close the connection when there are no results
            }
          })
        })
      })
    })
  }
});



// FETCH CREATOR STATS
app.get('/fetchStats', (req, res) => {
  const Target = req.query.id 

  if (Target) {
    
      let Followers = 0
      let Following = 0
      let Likes = 0
    
      const connection = mysql.createConnection(dbConfig);
    
    
      connection.query('SELECT * FROM following WHERE FOLLOWED_BY = ?', [Target], (error, following, fields) => {
        Following = following.length
        connection.query('SELECT * FROM following WHERE FOLLOWED = ?', [Target], (error, followed, fields) => {
          Followers = followed.length
          connection.query('SELECT * FROM likes WHERE OWNER_ID = ?', [Target], (error, likes, fields) => {
            connection.end()
            Likes = likes.length
    
          res.status(200).send({
            userFollowing: Following,
            userFollowers: Followers,
            userLikes: Likes
          });
        })
    
        })
      })

  }


})

app.post('/Azare/Fetch/Video/Random', (req, res) => {
  const connection = mysql.createConnection(dbConfig);
  
  connection.query(`SELECT * FROM videos ORDER BY RAND() LIMIT 1`, (error, Videos, fields) => {
    if (error) {
      connection.end()
      return res.status(400).send({ error:true, message: "Internal Server Error" })
    }

    if (Videos.length != 1) {
      return res.status(200).send({ error: true, message: "No videos has been uploaded so far." })
    }

    connection.query('SELECT USR_ID, USR_USERNAME, USR_IMAGE, USR_APPROVED FROM user_data WHERE USR_ID = ?', [Videos[0].OWNER_ID], (error, results, fields) => {
      connection.query('SELECT * FROM likes WHERE CONTENT_ID = ?', [Videos[0].ID], (error, likes, fields) => {
        connection.end()
        if (error) {
          return res.status(400).send({ error:true, message: "Internal Server Error" })
        }
  
        return res.status(200).send({ error:false, message: Videos, user: results, likes: likes })
      })
    })
  })
})

// CHECK IF IS FOLLOWING. OR IF THEY ARE THE OWNER OF THE ACCOUNT
app.get('/checkProfileActions', (req, res) => {
  const userID = req.query.id
  const sID = req.query.sID

  if (!req.session.ACCESS_TOKEN) {
    res.status(200).send({LoggedIn: false});
  }

  if (sID != "") {
    const connection = mysql.createConnection(dbConfig);
  
    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [userID], (error, results, fields) => {
      if (results.length == 1) {
        let isFollowing = false
        connection.query('SELECT * FROM following WHERE FOLLOWED = ? AND FOLLOWED_BY = ?', [userID, sID], (error, results, fields) => {
          if (results.length == 1) {
            isFollowing = true
          }
        })
        connection.end();
        bcrypt.compare(results[0].USR_ACS_TOKEN, req.session.ACCESS_TOKEN).then(VALID => {
          res.status(200).send({
            isOwner: VALID,
            Following: isFollowing
          });
        })
      }
    })
  } else {
    res.status(200).send({
      isOwner: false,
      Following: false
    });
  }

})


app.get('/followAcc', (req, res) => {
  const id = req.query.id;
  const sID = req.query.sID;

  if (id && sID) {
    const connection = mysql.createConnection(dbConfig);
    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [sID], (error, results, fields) => {
      const ENC_ACCESS_TOKEN = req.session.ACCESS_TOKEN

      bcrypt.compare(results[0].USR_ACS_TOKEN, ENC_ACCESS_TOKEN).then(VALID => {
        if (VALID) {
          connection.query('SELECT * FROM following WHERE FOLLOWED = ? AND FOLLOWED_BY = ?', [id, sID], (error, results, fields) => {
            if (results.length == 0) {
              connection.query(`INSERT INTO following (FOLLOWED, FOLLOWED_BY) VALUES ('${id}', '${sID}')`)
              connection.end();
              res.status(200).send({success: true })
            }
          })
        } else {
          res.status(403)
        }
      })
    })

  }

})



app.get('/unfollowAcc', (req, res) => {
  const id = req.query.id;
  const sID = req.query.sID;

  if (id && sID) {
    const connection = mysql.createConnection(dbConfig);

    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [sID], (error, results, fields) => {
      const ENC_ACCESS_TOKEN = req.session.ACCESS_TOKEN

      bcrypt.compare(results[0].USR_ACS_TOKEN, ENC_ACCESS_TOKEN).then(VALID => {
        if (VALID) {
          connection.query('SELECT * FROM following WHERE FOLLOWED = ? AND FOLLOWED_BY = ?', [id, sID], (error, checkIf, fields) => {
            if (results.length == 1) {
              const FLW_ID = checkIf[0].FLW_ID;
              const deleteQuery = `DELETE FROM following WHERE FLW_ID = ${FLW_ID}`;

              connection.query(deleteQuery, (error, result) => {
                if (error) {
                  console.error('Error deleting row:', error);
                  return;
                }
                connection.end();
                res.status(200).send({success: true })
              });

            }
          })
        } else {
          res.status(403)
        }
      })
    })

  }
  
})


app.post('/saveProfileStatus', (req, res) => {
  const ACCESS_TOKEN = req.session.ACCESS_TOKEN
  let userStatus = req.body.userStatus
  const userID = req.body.id
  const MultiAction = req.body.MultiAction

  const connection = mysql.createConnection(dbConfig);

  connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [userID], (error, results, fields) => {
    bcrypt.compare(results[0].USR_ACS_TOKEN, req.session.ACCESS_TOKEN).then(VALID => {
      if (VALID) {
        if (userStatus.length > 100) {
          userStatus = "No status yet."
        }
        if (userStatus == "") {
          userStatus = "No status yet."
        }
        connection.query(`UPDATE user_data SET USR_STATUS = "${userStatus}"  WHERE USR_ID = ${userID};`)
        connection.end()

        if (MultiAction) {
          return res.status(200).send({ err:false ,message: "All changes has been saved."})
        } else {
          return res.status(200).send({ err:false ,message: "Status has been updated."})
        }
      } else {
        res.render('/home')
      }
    })
  })
})

app.post('/saveProfileUsername', (req, res) => {
  const ACCESS_TOKEN = req.session.ACCESS_TOKEN
  let userUsername = req.body.userUsername.toLowerCase();
  const userID = req.body.id
  const MultiAction = req.body.MultiAction

  const connection = mysql.createConnection(dbConfig);

  if (userUsername.includes(" ")) {
    return res.status(200).send({ err:true ,message: "Username can't include spaces."})
  }

  connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [userID], (error, results, fields) => {
    bcrypt.compare(results[0].USR_ACS_TOKEN, req.session.ACCESS_TOKEN).then(VALID => {
      if (VALID) {

        if (userUsername == results[0].USR_USERNAME) {
          return res.status(200).send({ err:true ,message: "Username is already connected to your account."})
        }

        connection.query('SELECT * FROM user_data WHERE USR_USERNAME = ?', [userUsername], (error, exists, fields) => {
          if (exists.length == 0) {
            if (userUsername.length > 20) {
              return res.status(200).send({ err:true ,message: "Character limit exceeded."})
            }
            if (userUsername == "") {
              return res.status(200).send({ err:true ,message: "Username can't be empty."})
            }

            connection.query(`UPDATE user_data SET USR_USERNAME = "${userUsername}"  WHERE USR_ID = ${userID};`)
            connection.end()
    
            if (MultiAction) {
              return res.status(200).send({ err:false ,message: "All changes has been saved."})
            } else {
              return res.status(200).send({ err:false ,message: "Status has been updated."})
            }
          } else {
            connection.end()
            return res.status(200).send({ err:true ,message: "Username already taken."})
          }
        })
      } else {
        res.render('/home')
      }
    })
  })
})


////////////////////////


app.get('/fetchUser', (req, res) => {
  const userID = req.query.id;

  if (userID != "") {
    const connection = mysql.createConnection(dbConfig);
  
    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', [userID], (error, results, fields) => {
      if (error) {
        console.error('There was a problem with the MySQL query:', error);
        res.sendStatus(500);
        return;
      }

      if (results.length == 1) {
        res.status(200).send({
          username: results[0].USR_USERNAME,
          verified: results[0].USR_APPROVED,
          status: results[0].USR_STATUS,
          image: results[0].USR_IMAGE
        });
      } else {
        res.status(200).send({
          username: "Account does not exist",
          verified: false,
          status: "404",
          image: "default.png"
        });
      }
  
      connection.end();
      
    });
  }

});

app.get('/profile', (req, res) => {
  res.render('profile')
})

app.get('/edit', (req, res) => {
  res.render('edit')
})


app.get('/fetchEditPermissions', (req, res) => {
  const TargetID = req.query.id 

  if (!req.session.ACCESS_TOKEN) {
    return res.status(200).send({res:"nAuth"})
  }

  if (TargetID != "") {
    const connection = mysql.createConnection(dbConfig);
    
    // connect to the database
    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });
    connection.query('SELECT * FROM user_data WHERE USR_ID = ?', TargetID, (error, results, fields) => {
      connection.end()
      bcrypt.compare(results[0].USR_ACS_TOKEN, req.session.ACCESS_TOKEN).then(VALID => {
        if (VALID) {
          res.status(200).send({res:"aAuth"})
        } else {
          res.status(200).send({res:"nAuth"})
        }
      })
    })

  }
})









// LOGIN
app.post('/authenticate', (req, res) => {
  if (req.session.ACCESS_TOKEN) {
    // Already logged in

    const connection = mysql.createConnection(dbConfig);
    
    // connect to the database
    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });

    let SignedIn = false
    connection.query('SELECT * FROM user_data WHERE USR_ACS_TOKEN', [], (error, results, fields) => {
      connection.end();
      if (results) {
        results.forEach(item => {
          bcrypt.compare(item.USR_ACS_TOKEN, req.session.ACCESS_TOKEN).then(VALID => {
            if (VALID) {
              return res.send({ status: 200, action: true, id: item.USR_ID, username: item.USR_USERNAME, image: item.USR_IMAGE, verified: item.USR_APPROVED });
            }
          })
        });
        if (SignedIn == false) {
          //console.log(SignedIn)
          //ServerLog(`INVALID TOKEN: ${req.session.ACCESS_TOKEN}`)
          //res.clearCookie("ACCESS_TOKEN")
          //res.send({ status: 200, action: false });
          //res.end()
        }
      }
    })
  } else {
    res.send({ status: 200, action: false });
    res.end()
  }
})


// Authorization - Login Handler

app.post('/authorize', (req, res) => {
  // Not logged in

  const username = req.body.name;
  const password = req.body.password;
  
  if (username && password) {
    // create a connection to the database
    const connection = mysql.createConnection(dbConfig);
    
    // connect to the database
    connection.connect((error) => {
      if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
      }
    });

    Hash(password).then(hashedPassword => {

    // perform a query to check if the user is valid
    connection.query('SELECT * FROM user_data WHERE USR_USERNAME = ?', [username], (error, results, fields) => {
      if (error) {
        console.error('Error executing query:', error);
        return res.status(500).send('Internal server error.');
      }

      connection.end();

      if (results.length === 0) {
        return res.send({ status: 200, error: "uaP" });
      }

      bcrypt.compare(password, results[0].USR_PASSWORD)
        .then((match) => {

          if (match) {
            
            // Encrypt ACCESS_TOKEN and store in client cookies.
            Hash(results[0].USR_ACS_TOKEN).then(ACS => {
              req.session.ACCESS_TOKEN = ACS;
              ServerLog(`AUTHORIZED: ${results[0].USR_USERNAME} | ENCRYPTED ACCESS TOKEN: ${ACS}`)
              res.send({ status: 200, error: "AuaP" });
            })
            
            //generateAccessToken().then(token => console.log(token));

          } else {

            //ServerLog(`Denied access to client | USERNAME USED: ${username}`)
            res.send({ status: 200, error: "uaP" });
            
          }
        })
        .catch((error) => {
          console.error(error); 
          return res.status(500).send('Internal server error.');
        });
        
        connection.end();

      });
    });
    
    
  } else {
    return res.status(400).send('Invalid data.');
  }
  return
});

// REGISTRATION
app.post('/establishAuth', (req, res) => {

  const username = req.body.name.toLowerCase();
  const password = req.body.password;
  const confPassword = req.body.ConfPass;

  if (username && password && confPassword) {

    if (username.includes(" ")) {
      res.send({ status: 500, err: "true", content: "Username can't include spaces." });
    }

    if (username.length < 21 && password.length < 21 && confPassword.length < 21) {
      if (password === confPassword) {
        const connection = mysql.createConnection(dbConfig);

        // connect to the database
        connection.connect((error) => {
          if (error) {
            console.error('Error connecting to MySQL:', error);
            return;
          }
        });

        connection.query('SELECT * FROM user_data WHERE USR_USERNAME = ?', [username], (error, results, fields) => {
          if (error) {
            console.error('Error querying MySQL:', error);
            res.send({ status: 500, err: "true", content: "Internal server error." });
            return;
          }
          if (results.length === 0) {
            Hash(password).then(hashedPassword => {
              generateAccessToken().then(TOKEN => {
                connection.query(`INSERT INTO user_data (USR_ACS_TOKEN, USR_USERNAME, USR_PASSWORD) VALUES (?, ?, ?)`, [TOKEN, username, hashedPassword], (error, results, fields) => {
                  connection.end()
                  if (error) {
                    console.error('Error inserting into MySQL:', error);
                    res.send({ status: 500, err: "true", content: "Internal server error." });
                    return;
                  }
                  res.send({ status: 200, err: "false", content: "Account was created successfully!" });
                });
              });
            });
          } else {
            // ACCOUNT ALREADY EXISTS
            res.send({ status: 200, err: "true", content: "That username already exists." });
          }
        });
      } else {
        // PASSWORDS DON'T MATCH:
        res.send({ status: 200, err: "true", content: "Passwords do not match." });
      }
    } else {
      res.send({ status: 200, err: "true", content: "Input max length exceeded." });
    }
  } else {
    res.send({ status: 200, err: "true", content: "Incomplete input data." });
  }
});

















const PORT = 3000
const timestamp = new Date().getTime();
const dateString = new Date(timestamp).toLocaleString();

app.listen(PORT, () => {
    console.clear();
    ServerLog(`Running on port: ${PORT} | Started Timestamp: ${dateString} | Server Running: http://localhost:${PORT}`)
});
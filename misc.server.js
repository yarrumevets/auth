// -----------------------------------------------------------------------------

// // Hash Generator
// app.get("/api/hash/:seed", (req, res) => {
//   const seed = req.params["seed"];
//   var current_date = new Date().valueOf().toString();
//   var random = Math.random().toString();

//   console.log("seed: ", seed);
//   console.log("current_date: ", current_date);
//   console.log("random: ", random);

//   let hash = crypto
//     .createHmac("sha256", passwordSecret)
//     .update(seed)
//     .digest("hex");

//   console.log("hash: ", hash);

//   hash = crypto.createHmac("sha256", hash).update(current_date).digest("hex");

//   console.log("hash: ", hash);

//   hash = crypto.createHmac("sha256", hash).update(random).digest("hex");

//   console.log("hash: ", hash);

//   res.send(hash);
// });

// -----------------------------------------------------------------------------

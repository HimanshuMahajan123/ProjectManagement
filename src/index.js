import dotenv from "dotenv";
import app from "./app.js";
import connectDB from "./db/index.js";

dotenv.config({
  path: "./.env"
});


const port = process.env.PORT || 3000;

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`App is listening on port http://localhost:${port}`)
    })
  })
  .catch((err) => {
    console.error("Failed to connect to the database:", err);
    process.exit(1);
  })


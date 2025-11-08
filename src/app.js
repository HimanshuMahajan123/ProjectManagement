import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

//basic configurations
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

//CORS configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
}))


//import the routes
import healthCheckRouter from "./routes/healthcheck.routes.js";
app.use("/api/v1/healthcheck", healthCheckRouter);

import authRouter from "./routes/auth.routes.js";
app.use("/api/v1/auth", authRouter);

app.get('/', (req, res) => {
    res.send('Hello World!')
})

export default app;

// api/v1/healthcheck/user
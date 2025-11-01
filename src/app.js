import express from "express";
import cors from "cors";


const app = express();

//basic configurations
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

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

app.get('/', (req, res) => {
    res.send('Hello World!')
})

export default app;

// api/v1/healthcheck/user
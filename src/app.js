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


app.get('/', (req, res) => {
    res.send('Hello World!')
})

export default app;
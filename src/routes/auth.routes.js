import { Router } from "express";
import {login, logoutUser, registerUser} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userLoginValidator, userRegistrationValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";


const router = Router();

router.route("/register").post(userRegistrationValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator() , validate , login);
router.route("/logout").post(verifyJWT , logoutUser);

export default router;
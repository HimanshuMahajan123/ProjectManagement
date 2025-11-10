import { Router } from "express";
import { changeCurrentPassword, forgotPasswordRequest, getCurrentUser, login, logoutUser, refershAccessToken, registerUser, resendEmailVerification, resetForgottenPassword, verifyEmail } from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userChangeCurrentPasswordValidator, userForgotPasswordValidator, userLoginValidator, userRegistrationValidator, userResetForgottenPasswordValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";


const router = Router();

//unsecured routes
router.route("/register").post(userRegistrationValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refershAccessToken);
router.route("/forgot-password").post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
router.route("/reset-password/:resetToken").post(userResetForgottenPasswordValidator(), validate, resetForgottenPassword)

//secured routes
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/change-password").post(verifyJWT, userChangeCurrentPasswordValidator(), validate, changeCurrentPassword)
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);



export default router;
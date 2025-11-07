import { User } from '../models/user.models.js';
import { ApiResponse } from '../utils/api-response.js';
import { ApiError } from '../utils/api-error.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { sendEmail , emailVerificationMailgenContent } from '../utils/mail.js';

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating tokens");
    }
}

const registerUser = asyncHandler(async (req, res) => {

    const { username, email, password, role } = req.body;

    //check is user already exists
    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (existingUser) {
        throw new ApiError(409, "User already exists");
    }

    //create new user
    const user = await User.create({
        username,
        email,
        password,
        isEmailVerified: false
    });
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    //generate email verification token and save to user model 
    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: "Verify your email address",
        mailgenContent: emailVerificationMailgenContent(
            user?.username,
            `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unhashedToken}`
        )
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while creating user");
    }

    return res
        .status(201)
        .json(
            new ApiResponse(
                200,
                { user: createdUser },
                "User registered successfully. Please verify your email address."
            )
        )

});

export { registerUser };
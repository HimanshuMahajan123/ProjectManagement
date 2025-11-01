import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/asyncHandler.js";

/** 
const healthcheck = async (req, res , next) => {
    try {
        res
            .status(200)
            .json(new ApiResponse(200, { message: "API is healthy" }));
    } catch (error) {
        next(error);
    }
}
*/

const healthcheck = asyncHandler(async (req, res, next) => {
    res
        .status(200)
        .json(new ApiResponse(200, { message: "API is healthy" }));
})

export { healthcheck };
import JWT from "jsonwebtoken";
import userModel from "../models/userModel.js";

//Protected Routes token base
export const requireSignIn = (req, res, next) => {
  // Check if the Authorization header exists
  if (!req.headers.authorization) {
    // Return a 401 Unauthorized status with a message
    return res.status(401).json({ message: "Authorization header is missing" });
  }

  try {
    // Decode the JWT token using the secret key
    const decode = JWT.verify(
      req.headers.authorization, // Authorization header containing the JWT token
      process.env.JWT_SECRET // Secret key used to verify the token
    );

    //If the token is invalid or expired, it will throw an error that is caught by the catch block.
    req.user = decode; //If the token is valid, it decodes the payload (usually containing user data like ID, email, etc.) and attaches it to the req.user property.

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    // Handle specific errors (e.g., expired token)
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token has expired" });
    }

    // General error handling for invalid or malformed tokens
    return res.status(401).json({ message: "Invalid or malformed token" });
  }
};


//admin acceess
export const isAdmin = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (user.role !== 1) {
      return res.status(401).send({
        success: false,
        message: "UnAuthorized Access",
      });
    } else {
      next();
    }
  } catch (error) {
    console.log(error);
    res.status(401).send({
      success: false,
      error,
      message: "Error in admin middelware",
    });
  }
};

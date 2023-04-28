import User from "../models/user.model.js";
import createError from "../utils/createError.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
  try {
    const hash = bcrypt.hashSync(req.body.password, 5);
    const newUser = new User({
      ...req.body,
      password: hash,
    });

    await newUser.save();
    res.status(201).send("User has been created.");
  } catch (err) {
    next(err);
  }
};
export const login = async (req, res, next) => {
  try {
    
    const users = await User.findOne({ username: req.body.username });
    

    if (!users) return next(createError(404, "User not found!"));

    const isCorrect = bcrypt.compareSync(req.body.password, users.password);
    if (!isCorrect)
      return next(createError(400, "Wrong password or username!"));

    const token = jwt.sign(
      {
        id: users._id,
        isSeller: users.isSeller,
      },
      process.env.JWT_KEY
    );

    const { password, ...info } = users._doc;
    res
      .cookie("accessToken", token, {
        httpOnly: true,
      })
      .status(200)
      .send(info);
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res) => {
  res
    .clearCookie("accessToken", {
      sameSite: "none",
      secure: true,
    })
    .status(200)
    .send("User has been logged out.");
};

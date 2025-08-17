const jwt = require("jsonwebtoken");
const User = require("../models/user");

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.sendStatus(403);
    
    req.user = {
      id: user._id,
      username: user.username,
      role: user.role,
    };
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
};

module.exports = authenticateToken;
// roles.js
module.exports = function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        next();
    };
};

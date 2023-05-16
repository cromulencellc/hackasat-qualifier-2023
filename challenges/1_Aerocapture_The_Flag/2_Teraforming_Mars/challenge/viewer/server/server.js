const express = require('express');
const path = require('path');
const morgan = require("morgan");
const winston = require('winston');
const fs = require('fs');
const compression = require('compression');
const YAML = require('yaml');

const format = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
    winston.format.printf(
        (info) => `${info.timestamp} ${info.level}: ${info.message}`,
    ),
)

const transports = [
    new winston.transports.Console(),
    new winston.transports.File({
        filename: 'error.log',
        level: 'error',
    }),
    new winston.transports.File({ filename: 'server.log' }),
]

const Logger = winston.createLogger({
level: "info",
format,
transports,
})
  

const stream = {
    // Use the http severity
    write: (message) => Logger.info(message),
};
  
const skip = () => {
    return false
};

const morganMiddleware = morgan(
// Define message format string (this is the default one).
// The message format is made from tokens, and each token is
// defined inside the Morgan library.
// You can create your custom token to show what do you want from a request.
    ":remote-addr :method :url :status - :response-time ms",
    // Options: in this case, I overwrote the stream and the skip logic.
    // See the methods above.
    { stream, skip }
);
const PORT = process.env.PORT || 8080;

process.on ("SIGINT", function(){
    Logger.info("Ctrl+C recieved, exiting");
    process.exit(1);
});

// Setup Web Server
Logger.info("Starting Webserver")
const app = express();
app.set('trust proxy', true)
app.use(morganMiddleware);
app.use(compression());
app.use(express.static('dist/', {maxAge: 86400}));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/dist/index.html'));
});

app.listen(PORT, () => {
    Logger.info("Server listening on port: " + PORT);
});

// Imports
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const cors = require('cors')
const helmet = require('helmet')
const xss = require('xss-clean')
const compression = require('compression')
const fileUpload = require('express-fileupload')

// Import routes
const authRoute = require('./routes/auth')
const entitiesRoute = require('./routes/entities')

// Define Port
const port = process.env.PORT || 3000

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))

// use Helmet!
app.use(helmet())

// use xss!
app.use(xss())

// use cors
app.use(cors())

// compress
app.use(compression())

// grant access to upload file
app.use(
  fileUpload({
    useTempFiles: true,
    tempFileDir: '/tmp/'
  })
)

// Connect to db
mongoose.connect(
  process.env.DB_CONNECTION,
  { useNewUrlParser: true },
  () => console.log('Connected to DB')
)

// Routes
app.get('/', (req, res) => {
  res.send('Hello World!')
})
app.use('/auth', authRoute)
app.use('/entities', entitiesRoute)

// Error handling wrong routes
app.use('*', (req, res) => {
  res.status(404).send('404 Not Found')
})

// Listen
app.listen(port)

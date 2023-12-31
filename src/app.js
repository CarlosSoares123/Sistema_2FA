const express = require('express')
const authRoutes = require('./routes/authRoutes')
const cors = require('cors')
const morgan = require('morgan')

const app = express()
app.use(express.json())
app.use(cors())
app.use(morgan('dev'))

app.use('/auth', authRoutes)

module.exports = app

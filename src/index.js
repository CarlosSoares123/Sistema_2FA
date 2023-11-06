const app = require('./app')
const database = require('../database/models')
const port = process.env.NODE_ENV === 'test' ? 9001 : process.env.PORT || 8000

const server = app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`)
})

module.exports = server

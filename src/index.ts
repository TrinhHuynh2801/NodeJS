import express, { NextFunction, Request, Response } from 'express'
import usersRouter from '~/routes/users.routes'
import databaseService from './services/database.services'
import { defaultErrorHandler } from './middlewares/errors.middlewares'
const app = express()
const port = 3000

app.use(express.json())
app.use('/users', usersRouter)
app.use(defaultErrorHandler)
databaseService.connect()

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT,REGISTRY_PORT } from "../config";
import axios from "axios";


export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());
  let lastReceivedMessage:any = null;
  let lastSentMessage:any = null;


  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({result:lastReceivedMessage});
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({result:lastSentMessage});
  });

  _user.post("/message",(req,res)=>{
    const {message} = req.body;
    if(!message)
        res.status(400).send("Message is required");
    lastReceivedMessage = message;
    res.status(200).send("success");
  });


  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

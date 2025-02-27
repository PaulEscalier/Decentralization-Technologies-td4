import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT,REGISTRY_PORT } from "../config";
import { webcrypto } from "crypto";
import { symEncrypt, rsaEncrypt } from "../crypto";
import axios from "axios";
import {Node} from "@/src/registry/registry";

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

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    if (!message || !destinationUserId) {
      res.status(400).send("Message and destinationUserId are required");
    }

    try {
      // Step 1: Create a random circuit of 3 distinct nodes
      const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const registry: Node[] = registryResponse.data.nodes;
      const nodes = registry.sort(() => 0.5 - Math.random()).slice(0, 3);

      // Step 2: Create each layer of encryption
      let encryptedMessage = btoa(message);
      for (const node of nodes) {
        const symKey = await webcrypto.subtle.generateKey(
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        const iv = webcrypto.getRandomValues(new Uint8Array(16));
        const symEncrypted = await symEncrypt(symKey, encryptedMessage);
        const rsaEncryptedKey = await rsaEncrypt(encryptedMessage,node.pubKey);

        // Encode the destination as a string of 10 characters with leading zeros
        const destination = (BASE_USER_PORT + destinationUserId).toString().padStart(10, '0');

        // Concatenate the destination and the encrypted message, then encrypt with the symmetric key
        const combinedMessage = `${destination}${symEncrypted}`;
        const finalEncryptedMessage = await symEncrypt(symKey, combinedMessage);

        // Concatenate the encrypted symmetric key with the final encrypted message
        encryptedMessage = `${rsaEncryptedKey}.${finalEncryptedMessage}`;
      }

      // Step 3: Forward the encrypted message to the entry node
      const entryNode = nodes[0];
      await axios.post(`http://localhost:${entryNode.nodeId}/message`, {
        message: encryptedMessage,
      });

      res.status(200).send("Message sent successfully");
      lastSentMessage = message;
    } catch (error) {
      res.status(500).send("An error occurred while sending the message");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

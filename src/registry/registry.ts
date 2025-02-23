import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import {exportPrvKey, exportPubKey, generateRsaKeyPair} from "../crypto";
import { generateKeyPairSync } from 'crypto';

export type Node = { nodeId: number; pubKey: string; privateKey: any };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodeRegistry: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  _registry.post('/registerNode', async (req, res) => {
    const { nodeId } = req.body;
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubKey = await exportPubKey(publicKey);
    const prvKey = await exportPrvKey(privateKey);

    if (nodeRegistry.some(node => node.pubKey === pubKey)) {
      res.status(400).json({ error: 'Public key must be unique' });
    }

    nodeRegistry.push({ nodeId, pubKey, privateKey: prvKey });
    res.status(200).json({ message: 'Node registered successfully' });
  });


  _registry.get("/getPrivateKey", (req, res) => {
    const { nodeId } = req.query;
    const node = nodeRegistry.find(node => node.nodeId === Number(nodeId));
    if (!node) {
      res.status(404).json({ error: 'Node not found' });
    }else
      res.json({ result: node.privateKey });
  });


  _registry.get("/getNodeRegistry", (req, res:Response<GetNodeRegistryBody>) => {
    const nodes = nodeRegistry.map(({ nodeId, pubKey, privateKey }) => ({ nodeId, pubKey, privateKey }));
    res.json({ nodes });
  });

  const { publicKey, privateKey } = await generateRsaKeyPair();




  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import { webcrypto } from "crypto";
import {exportPrvKey, exportPubKey, generateRsaKeyPair} from "../crypto";

export type Node = { nodeId: number; pubKey: string; pvKey: string };

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
    const { nodeId, publicKey, privateKey } = req.body;

    if (nodeRegistry.some(node => node.pubKey === publicKey)) {
      res.status(400).json({ error: 'Public key must be unique' });
    }

    nodeRegistry.push({ nodeId:nodeId, pubKey:privateKey,pvKey:privateKey });
    res.status(200).json({ message: 'Node registered successfully' });
  });


  _registry.get("/getPrivateKey", (req, res) => {
    const { nodeId } = req.query;
    const node = nodeRegistry.find(node => node.nodeId === Number(nodeId));
    if (!node) {
      res.status(404).json({ error: 'Node not found' });
    }else
      res.json({ result: node.pvKey });
  });


  _registry.get("/getNodeRegistry", (req, res: Response) => {
    const nodes = nodeRegistry.map(({ nodeId, pubKey }) => ({ nodeId, pubKey }));
    res.json({ nodes });
  });

  const { publicKey, privateKey } = await generateRsaKeyPair();




  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
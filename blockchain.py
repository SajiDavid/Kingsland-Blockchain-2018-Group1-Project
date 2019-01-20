import hashlib
import json
import requests
from time import time
from uuid import uuid4
from urllib.parse import urlparse
from flask import Flask
from flask import jsonify
import datetime
from flask import request
import random
import os.path
import pickle
import hashlib, binascii
import binascii
import threading
from pycoin.ecdsa import generator_secp256k1, sign, verify
from time import sleep
from threading import Timer
from threading import Thread

class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False
		
class NodeClass():
	def __init__(self, node_id, url):
		self.nodeId = node_id
		self.URL = url

class BlockClass():
	def __init__(self, index, transactions, prevblockhash, minedby, insertCoinbase):
		self.Index = index
		self.Transactions = transactions.copy()
		# All mining blocks except the genesis block need to insert a coinbase transaction to reward the miner
		self.Difficulty = BlockChain.CurrentDifficulty
		self.PrevBlockHash = prevblockhash
		self.Minedby = minedby
		if insertCoinbase > 0:
			self.InsertCoinbaseTransaction( insertCoinbase, minedby )
		self.BlockDataHash = self.computeBlockDataHash()
	
	def fill_in_block(self, index, transactions, difficulty, prev_block_hash, minedby, block_data_hash, nonce, date_created, block_hash):
		self.Index = index
		self.Transactions = transactions.copy()
		self.Difficulty = difficulty
		self.PrevBlockHash = prev_block_hash
		self.Minedby = minedby
		self.BlockDataHash = block_data_hash
		self.Nonce = nonce
		self.DateCreated = date_created
		self.BlockHash = block_hash
	
	def computeReward( self ):
		reward = 0
		for i in range(len(self.Transactions)):
			reward += self.Transactions[i].Fee
		return BlockChain.MiningReward + reward
		
	
	def InsertCoinbaseTransaction(self, mode, miner ):
		frm = 40 * "0"
		to = miner
		value = self.computeReward()
		fee = 0
		x = datetime.datetime.now()
		date_created = x.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
		data = "coinbase tx"
		sender_pub_key = 65 * "0"
		sender_signature = 64 * "0"
		coinbase_transaction = TransactionClass(frm, to, value, fee, date_created, data, sender_pub_key, sender_signature)
		self.Transactions.insert(0, coinbase_transaction)	

	def obtainMinerAddr(self, mode):
		if mode==1:
			r = random.randint(4, 9)
			addr = 40*str(r)
		else:
			addr = self.Minedby
		return addr	
	
	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__, 
			sort_keys=True, indent=4)
	
	def build_header_bin(self):
		return (str(self.Index) +
			str(self.Transactions) +
			str(self.Difficulty) +
			str(self.PrevBlockHash) + 
			str(self.Minedby)).encode()

	def computeBlockDataHash(self):
		header_bin = self.build_header_bin()
		outer_hash = hashlib.sha256(header_bin).hexdigest()
		return outer_hash
	
	def setGenesisBlock(self):
		self.Nonce = 0
		x = datetime.datetime.now()
		self.DateCreated = x.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
		tail_bin = (str(self.PrevBlockHash)+str(self.DateCreated)+str(self.Nonce)).encode()
		outer_hash = hashlib.sha256(tail_bin).hexdigest()
		self.BlockHash = outer_hash

	def build_body_bin(self):
		self.Nonce += 1
		x = datetime.datetime.now()
		self.DateCreated = x.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
		return (str(self.BlockDataHash) +
			str(self.DateCreated)+
			str(self.Nonce)).encode()

	def get_body_bin(self):
		return (str(self.BlockDataHash) +
			str(self.DateCreated)+
			str(self.Nonce)).encode()

	def mining(self):
		"""Parameter:
		difficulty : defines mining difficulty
		Return value:
		hash of the mined block
		"""
		difficulty_string = '0' * self.Difficulty
		self.Nonce = 0
		outer_hash = '11'
		while outer_hash[:self.Difficulty] != difficulty_string:
			body_bin = self.build_body_bin()
			outer_hash = hashlib.sha256(body_bin).hexdigest()
		self.BlockHash = outer_hash
		for i in range(len(self.Transactions)):
			self.Transactions[i].fill_mined_trans(self.Index, i, True)

	@staticmethod
	def verify_nonce_hash(block_data_hash, date_created, nonce, block_hash):
		body_bin = (str(block_data_hash)+str(date_created)+str(nonce)).encode()
		print( "body_bin = ", body_bin )
		outer_hash = hashlib.sha256(body_bin).hexdigest()
		print( "outer_hash = ", outer_hash )
		return block_hash==outer_hash
	
	def valid_nonce(self):
		body_bin = self.get_body_bin()
		outer_hash = hashlib.sha256(body_bin).hexdigest()
		return self.BlockHash==outer_hash
	
	@property
	def thisBlockHash(self):
		# Returns the BlockHash of the block
		return self.BlockHash
	
class TransactionClass():
	def __init__(self, frm, to, value, fee, date_created, data, sender_pub_key, sender_signature):
		self.From = frm
		self.To = to
		self.Value = value
		self.Fee = fee
		self.DateCreated = date_created
		self.Data = data
		self.SenderPubKey = sender_pub_key
		self.SenderSignature = sender_signature
		self.TransactionDataHash = self.computeTransDataHash()
		self.minedInBlockIndex = None
		self.TransferSuccessful = None	
		
	def fill_mined_trans(self, blockIndex, transIndex, random_mode):
		self.minedInBlockIndex = blockIndex
		if random_mode:
			v = random.randrange(6)
			if v==0 and transIndex>0:
				self.TransferSuccessful = False	
			else:	
				self.TransferSuccessful = True
		else:
			self.TransferSuccessful = True	

	def fill_in_transactions(self, frm, to, value, fee, date_created, data, sender_pub_key, sender_signature, trans_data_hash, mined_in_block_index, transfer_successful): 
		self.From = frm
		self.To = to
		self.Value = value
		self.Fee = fee
		self.DateCreated = date_created
		self.Data = data
		self.SenderPubKey = sender_pub_key
		self.SenderSignature = sender_signature
		self.TransactionDataHash = trans_data_hash
		self.minedInBlockIndex = mined_in_block_index
		self.TransferSuccessful = transfer_successful	
				
	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__, 
			sort_keys=True, indent=4)
	
	def build_trans_bin(self):
		return (str(self.From) +
			str(self.To)+
			str(self.Value) +
			str(self.Fee) +
			str(self.DateCreated) +
			str(self.Data) +
			str(self.SenderPubKey)).encode()

	def computeTransDataHash(self):
		trans_bin = self.build_trans_bin()
		outer_hash = hashlib.sha256(trans_bin).hexdigest()
		return outer_hash

	def matchHash(self, hashvalue):
		if self.TransactionDataHash==hashvalue:
			return True
		else:
			return False		

	def matchAddr(self, addr):
		if self.From==addr or self.To==addr:
			return True
		else:
			return False		

class BlockChain():
	About = "KingslandUniChain/1.0-python"
	CurrentDifficulty = 4
	MiningReward = 5000000

	def __init__(self, host, file1, file2, load):
		self.lock = threading.Lock()
		self.Host = host
		self.blockchain_file = file1
		self.transaction_file = file2
		self.nodes = set()
		self.chain = []
		self.candidate_blocks_pool = dict()
		print( "self.chain is initialized..." )
		self.pending_transactions = []
		if not load:
			# Generate a globally unique address for this node
			x = datetime.datetime.now()
			node_id = x.strftime('%Y%m%d_%H%M%S%f')[:-3] + '_' + str(uuid4()).replace('-','')
			node_id = node_id.encode()
			outer_hash = hashlib.sha256(node_id).hexdigest()
			self.nodeId = outer_hash
			print( "Before self.create_genesis_block()..." )
			# Create the genesis block
			self.create_genesis_block()
			print( "# of blocks is ", len(self.chain) ) 
		else:
			self.load_data( file1, file2 )
			print( "After self.load_data()..." )	

	def save_chain(self, file1):
		try:
			with open(file1, mode = 'w') as f:
				f.write(json.dumps(self.chain, default=lambda x: x.__dict__))
				f.write('\n')
				f.write(self.nodeId)
				f.write('\n')
				f.write(self.chainId)
				f.write('\n')
		except IOError:
			print('Saving blockchain file failed!')

	def save_transaction(self, file2):
		try:
			with open(file2, mode = 'w') as f:
				f.write(json.dumps(self.pending_transactions, default=lambda x: x.__dict__))
				f.write('\n')
		except IOError:
			print('Saving transaction file failed!')

	def load_chain(self, data):
		# load blockchain
		blocks = json.loads(data)
		updated_blockchain = []
		for block in blocks:
			converted_tx = []
			for tx in block['Transactions']: 
				trans = TransactionClass(tx['From'], tx['To'], tx['Value'], tx['Fee'], tx['DateCreated'], tx['Data'], tx['SenderPubKey'], tx['SenderSignature'])
				trans.fill_in_transactions(tx['From'], tx['To'], tx['Value'], tx['Fee'], tx['DateCreated'], tx['Data'], tx['SenderPubKey'], tx['SenderSignature'], tx['TransactionDataHash'], tx['minedInBlockIndex'], tx['TransferSuccessful'])
				converted_tx.append( trans )
			updated_block = BlockClass(block['Index'], converted_tx, block['PrevBlockHash'], block["Minedby"], 0)
			updated_block.fill_in_block(block['Index'], converted_tx, block['Difficulty'], block['PrevBlockHash'], block['Minedby'], block['BlockDataHash'], block['Nonce'], block['DateCreated'], block['BlockHash'])
			updated_blockchain.append(updated_block)
		blocks = updated_blockchain
		return blocks

	def synchronize_chain(self, node):
		print( "synchronize_chain(): before requests.get()-->node ", node )
		response = requests.get(f'http://{node}/chain')
		print( "synchronize_chain(): response.status_code = ", response.status_code )
		if response.status_code == 200:
			new_chain = self.load_chain(response.json()['chain'])
			new_chain_id = response.json()['chainId']
			new_transactions = self.load_trans(response.json()['transactions'])
			self.lock.acquire()	# lock the thread to refresh the entire blockchain and pending transactions
			self.chain = new_chain
			# self.pending_transactions = new_transactions
			self.chainId = new_chain_id
			self.save_chain( self.blockchain_file )
			self.save_transaction( self.transaction_file )
			self.lock.release()	# unlock the resources
			crashed_nodes = []
			for peer in self.nodes:
				# no need to notify the sender
				if peer.URL==node:
					continue
				else:
					if not self.notify_peer( peer ):
						crashed_nodes.append( peer )
			for peer in crashed_nodes:
				self.nodes.discard( peer )
					
	def notify_peer(self, peer):
		# data to be sent to api 
		headers = {
			'Content-Type': 'application/json'
		}
		data = {
			"blocksCount": len(self.chain),
			"cumulativeDifficulty": self.getCumulativeDifficulty(),
			"nodeUrl": "http://" + self.Host,		
		} 
		node = peer.URL
		destURL = f'http://{node}/peers/notify-new-block'
		print( "notify_peer(): destURL = ", destURL )
		sess = requests.session()
		try:
			response = sess.post(url=destURL, headers=headers, json=data)
		except:
			print( "The node {node} is gone!" )
			return False
		if response.status_code!=200:
			return False
		else:
			return True
		

	def load_trans(self, data):
		# load pending transaction pool
		transactions = json.loads(data)
		updated_transactions = []
		for tx in transactions:
			trans = TransactionClass(tx['From'], tx['To'], tx['Value'], tx['Fee'], tx['DateCreated'], tx['Data'], tx['SenderPubKey'], tx['SenderSignature'])
			trans.fill_in_transactions(tx['From'], tx['To'], tx['Value'], tx['Fee'], tx['DateCreated'], tx['Data'], tx['SenderPubKey'], tx['SenderSignature'], tx['TransactionDataHash'], tx['minedInBlockIndex'], tx['TransferSuccessful'])
			updated_transactions.append( trans )
		transactions = updated_transactions
		return transactions
	
	def load_data(self, file1, file2):
		try:
			with open(file1, mode='r') as f:
				file_content = f.readlines()
				# load blockchain
				self.chain = self.load_chain(file_content[0][:-1])
				# load nodeId and chainId		
				self.nodeId = file_content[1][:-1]
				self.chainId = file_content[2][:-1]
			with open(file2, mode='r') as f:
				file_content = f.readlines()
				# load pending transaction pool
				self.pending_transactions = self.load_trans(file_content[0][:-1])
		except (IOError, IndexError):
			print( "Fail to load data!" )

	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__, 
			sort_keys=True, indent=4)

	def form_candidate_block(self, miner_address):
		index = len( self.chain )
		transactions = self.pending_transactions.copy()
		prevblockhash = self.last_block.thisBlockHash
		minedby = miner_address
		print( "form_candidate_block(): # of transactions is ", len(transactions) )
		block = BlockClass( index, transactions, prevblockhash, minedby, 2 )
		return block
		
	def create_genesis_block(self):
		# hardcode those initial Faucet transactions
		Trans = []
		x = datetime.datetime.now()
		date_created = x.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
		transaction = TransactionClass("0000000000000000000000000000000000000000", 
			"c3293572dbe6ebc60de4a20ed0e21446cae66b17", 
			1000000000, 0, date_created, 
			"genesis tx", 
			"00000000000000000000000000000000000000000000000000000000000000000", 
			"0000000000000000000000000000000000000000000000000000000000000000"
		)
		transaction.TransferSuccessful = True
		Trans.append(transaction) 
		block = BlockClass(0, Trans, '0', "0000000000000000000000000000000000000000", 0)
		block.setGenesisBlock()
		self.chainId = block.BlockHash
		self.chain.append(block)
		self.save_chain( self.blockchain_file )
		return block

	def clear_pending_transactions(self):
		self.pending_transactions.clear()
	
	def new_block(self, minedby):
		# Create a new Block and adds it to the chain
		index = len(self.chain)
		transactions = self.pending_transactions.copy()
		prevblockhash = self.last_block.thisBlockHash
		block = BlockClass(index, transactions, prevblockhash, minedby, 1)
		block.mining()
		self.clear_pending_transactions()
		self.chain.append(block)
		self.save_chain( self.blockchain_file )
		self.save_transaction( self.transaction_file )
		return block

	def trim_head_pending_transactions( self, N ):
		for i in range(N):
			del self.pending_transactions[0]

	def broadcast_new_block( self ):
		crashed_nodes = []
		for peer in self.nodes:
			if not self.notify_peer( peer ):
				crashed_nodes.append( peer )
		for peer in crashed_nodes:
			self.nodes.discard( peer )
		
	def doHeartBeat( self ):
		crashed_nodes = []
		for peer in self.nodes:
			if not self.ping_peer( peer ):
				crashed_nodes.append( peer )
		for peer in crashed_nodes:
			self.nodes.discard( peer )
		
	def ping_peer( self, node ):
		try:
			response = requests.get(f'http://{node.URL}/heartbeat')
			if response.status_code==200:
				return True
			else:
				return False	
		except:
			print( "Fail to ping ..." )
			return False
		
	def append_block( self, block_data_hash, date_created, nonce, block_hash ):
		block = self.candidate_blocks_pool[block_data_hash]
		if block.Index!=len(self.chain):	# just in case any dirty data has come in
			return -1
		block.Nonce = nonce
		block.DateCreated = date_created
		block.BlockHash = block_hash
		for i in range(len(block.Transactions)):
			block.Transactions[i].fill_mined_trans(block.Index, i, False)
		self.candidate_blocks_pool.clear()	# clear the entire mining block pool
		self.trim_head_pending_transactions( len( block.Transactions ) - 1 )	# remove all the mined transactions
		self.chain.append( block )
		self.save_chain( self.blockchain_file )
		self.save_transaction( self.transaction_file )
		return block.computeReward()
	
	@property
	def last_block(self):
		# Returns the last Block in the chain
		return self.chain[-1]
		
	def append_transaction(self, transaction):
		self.pending_transactions.append(transaction)
		self.save_transaction( self.transaction_file ) 

	def connect_to_node( self, node ):
		# data to be sent to api 
		headers = {
			'Content-Type': 'application/json'
		}
		data = {
			'host': self.Host,
			'nodeId': self.nodeId  
		} 
		destURL = f'http://{node}/peers/shakehands'
		print( "connect_to_node(): destURL = ", destURL )
		sess = requests.session()
		response = sess.post(url=destURL, headers=headers, json=data)
		if response.status_code == 200:
			ret_data = response.json()
			peer = NodeClass( ret_data['nodeId'], ret_data['host'] )
			return peer
		else:
			return None
			
	def find_node( self, node ):
		for peer in self.nodes:
			if peer.URL==node:
				return peer
		return None
	
	def getCumulativeDifficulty(self):
		difficulty = 0
		for i in range(len(self.chain)):
			difficulty += self.chain[i].Difficulty
		return difficulty	
	
	def register_peer( self, node ):
		# check if a node has already been connected
		if not self.find_node( node ) is None:
			return 1
		peer = self.connect_to_node( node )	
		if peer is None:	
			return 2
		else:	
			self.nodes.add(peer)
			self.resolve_conflict()
			return 0
		
	def add_peer( self, node_id, url ):
		# check if a node has already been connected
		peer = self.find_node( url )
		if peer is None:
			peer = NodeClass( node_id, url )
			self.nodes.add(peer)
		else:
			peer.nodeId = node_id
		self.resolve_conflict()
		
	def valid_chain(self, chain):
		"""
		Determine if a given blockchain is valid
		:param chain: A blockchain
		:return: True if valid, False if not
		"""	
		last_block = chain[0]
		current_index = 1
		
		while current_index < len(chain):
			block = chain[current_index];
			print(f'{last_block}')
			print(f'{block}')
			# Check that the hash of the block is correct
			if block.PrevBlockHash!=last_block.BlockHash:
				return False
			# Check that the Proof of Work is correct
			if not block.valid_nonce():
				return False
			last_block = block
			current_index += 1
		return True	

	@staticmethod
	def public_key_compressed_to_address(public_key_compressed):
		return ripemd160(public_key_compressed)
		
	@staticmethod	
	def valid_signature(pub_key, tran_hash, tran_signagure):
		valid = verify(generator_secp256k1, pub_key, tran_hash, tran_signagure)
		return valid
	
	# meanwhile checking the duplication of a Trans_Data_Hash value
	def checkBalanceHash(self, addr, trans_data_hash):
		Faucet_Account = self.chain[0].Transactions[0].To
		bal_dict = dict()
		bal = 0
		safeBalance = 0
		confirmedBalance = 0
		pendingBalance = 0
		duplicate_trans = False
		for i in range(len(blockchain.chain)):
			for j in range(len(blockchain.chain[i].Transactions)):
				trans = blockchain.chain[i].Transactions[j]
				if trans.TransactionDataHash==trans_data_hash:
					duplicate_trans = True		
				if trans.matchAddr(addr):
					if trans.From==addr:
						if trans.TransferSuccessful:
							if trans.From!=Faucet_Account and trans.To!=Faucet_Account:
								bal -= (int(trans.Value)+int(trans.Fee))
							else:	# Faucet transation will not count the fee
								bal -= int(trans.Value)
							if i>len(blockchain.chain)-6 and (trans.From==Faucet_Account or trans.To==Faucet_Account):
								safeBalance -= int(trans.Value)		# Faucet transaction is waived from 6-block rule
						else:
							if trans.From!=Faucet_Account and trans.To!=Faucet_Account:
								bal -= int(trans.Fee)
					else:
						bal += int(trans.Value)
						if i>len(blockchain.chain)-6 and (trans.From==Faucet_Account or trans.To==Faucet_Account):
							safeBalance += int(trans.Value)		# Faucet transaction is waived from 6-block rule
			if i==len(blockchain.chain)-6:
				safeBalance = bal
		bal_dict["safeBalance"] = safeBalance
		confirmedBalance = bal
		bal_dict["confirmedBalance"] = confirmedBalance
		for k in range(len(blockchain.pending_transactions)):	
			trans = blockchain.pending_transactions[k]
			if trans.TransactionDataHash==trans_data_hash:
				duplicate_trans = True		
			if trans.matchAddr(addr):
				if trans.From==addr:
					if trans.From!=Faucet_Account and trans.To!=Faucet_Account:
						bal -= (int(trans.Value)+int(trans.Fee))
					else:	# Faucet transation will not count the fee
						bal -= int(trans.Value)
				else:
					bal += int(trans.Value)
		pendingBalance = bal
		bal_dict["pendingBalance"] = pendingBalance
		bal_dict["duplicateTrans"] = duplicate_trans
		return bal_dict

	def resolve_conflict(self):
		"""
		This is our consensus algorithm, it resolves conflicts 
		by replacing our chain with the longest one in the network
		:return: True if our chain was replaced, False if not
		"""
		neighbours = self.nodes
		new_chain = None
		# We're only looking for chains longer than ours
		my_chain_difficulty = self.getCumulativeDifficulty()
		# Grab and verify the chains from all the nodes in our network
		for peer in neighbours:
			node = peer.URL
			response = requests.get(f'http://{node}/chain')
			if response.status_code == 200:
				other_chain_difficulty = response.json()['chain_difficulty']
				other_chain = self.load_chain(response.json()['chain'])
				other_chain_id = response.json()['chainId']
				other_transactions_length = response.json()['transaction_length']
				other_transactions = self.load_trans(response.json()['transactions'])
				# Check if the length is longer and the chain is valid
				if other_chain_difficulty > my_chain_difficulty and self.valid_chain(other_chain):
					my_chain_difficulty = other_chain_difficulty
					new_chain = other_chain
		# Replace our chain if we have discovered a new, valid chain, longer than ours
		if new_chain:
			self.lock.acquire()	# lock for thread safety
			self.chain = new_chain
			# self.pending_transactions = other_transactions
			self.chainId = other_chain_id
			self.save_chain( self.blockchain_file )
			self.save_transaction( self.transaction_file )
			self.lock.release()	# unlock
			return True
		else:
			return False	
	
	@property
	def last_block(self):
		# Returns the last Block in the chain
		return self.chain[-1]
	
	def proof_of_work(self, last_proof):
		proof = 0
		
		while not self.valid_proof(last_proof, proof):
			proof += 1
		return proof
	
	@staticmethod
	def valid_proof(last_proof, proof):
		guess = f'{last_proof}{proof}'.encode()
		guess_hash = hashlib.sha256(guess).hexdigest()
		return guess_hash[:1] == "0"

	@staticmethod
	def valid_addr(addr):
		if len(addr)!=40:
			return False
		for a in addr:
			if a>='0' and a<='9' or a>='A' and a<='F' or a>='a' and a<='f':
				continue
			else:
				return False
		return True
		
# Instance our Node
app = Flask(__name__)

@app.route('/mine', methods = ["GET"])
def mine():
	r = random.randint(4, 9)
	minedBy = 40*str(r)
	blockchain.lock.acquire()	# lock the operations below, to guarantee the thread safety of blockchain mining	
	block = blockchain.new_block(minedBy)
	blockchain.lock.release()	# unlock the blockchain resource
	blockchain.broadcast_new_block()
	trans = json.dumps(block.Transactions, default=lambda x: x.__dict__)
	response = {
		'message' : 'New block Forged',
		'index' : block.Index,
		'transactions_num' : len(block.Transactions),
		'transactions' : trans,
		'nonce' : block.Nonce,
		'previous_hash' : block.PrevBlockHash,
		'block_hash' : block.BlockHash
	}	
	return jsonify(response), 200

@app.route('/mining/get-mining-job/<MinerAddress>', methods = ["GET"])
def get_mining_job(MinerAddress):
	block = blockchain.form_candidate_block( MinerAddress )
	print( "get_mining_job(): # of transactions is ", len(block.Transactions) )
	# push the candidate block into the pool
	blockchain.candidate_blocks_pool[block.BlockDataHash] = block
	print( "block_data_cash = ", block.BlockDataHash )
	response = {
		"index": len(blockchain.chain),
		"transactionsIncluded": len(block.Transactions),
		"difficulty": block.Difficulty,	
		"expectedReward": block.Transactions[0].Value,
		"rewardAddress": MinerAddress,
		"blockDataHash": block.BlockDataHash
	}	
	return jsonify(response), 200

@app.route('/mining/submit-mined-block', methods = ['POST'])
def submit_mined_block():
	values = json.loads( request.data )
	block_data_hash = values.get('blockDataHash')
	print( "block_data_hash = ", block_data_hash )
	date_created = values.get('dateCreated')
	nonce = values.get('nonce')
	block_hash = values.get('blockHash')
	if not BlockClass.verify_nonce_hash(block_data_hash, date_created, nonce, block_hash):
		response = {
			"errorMsg": "Bad Request: fail to verify the block hash value"
		}
		code = 400
		return jsonify(response), code
	blockchain.lock.acquire()	# lock the operations below, to guarantee the thread safety of blockchain mining	
	if not block_data_hash in blockchain.candidate_blocks_pool:
		blockchain.lock.release()
		response = {
			"errorMsg": "Block not found or already mined"
		}
		code = 404
		return jsonify(response), code
	reward = blockchain.append_block( block_data_hash, date_created, nonce, block_hash )
	blockchain.lock.release()	# unlock the blockchain resource
	print( "blockchain length = ", len(blockchain.chain) )
	thread = Thread(target = blockchain.broadcast_new_block)
	thread.start()	
	response = {
		"message": "Block accepted, reward paid: " + str(reward) + " microcoins"
	}
	code = 200
	return jsonify(response), code
	
@app.route('/transactions/send', methods = ["POST"])
def send_transaction():
	values = json.loads( request.data )
	required = ['from', 'to', 'value', 'fee', 'dateCreated', 'data', 'senderPubKey', 'senderSignature']
	
	if not all(k in values for k in required):
		response = { "errorMsg": "Invalid transaction: some field(s) are missing" }
		return jsonify(response), 400
	# check whether balance of the sender account is enough	
	sender = values['from']
	value = values['value']
	fee = values['fee']
	pub_key = values['senderPubKey']
	# pub_key = int( pub_key, 16 )
	tran_signature = values['senderSignature']
	tran_signature = [int(tran_signature[0], 16), int(tran_signature[1], 16)]
	transaction = TransactionClass(values['from'], values['to'], values['value'], values['fee'], values['dateCreated'], values['data'], values['senderPubKey'], values['senderSignature'])
	bal_dict = blockchain.checkBalanceHash(sender, transaction.TransactionDataHash)
	if int(bal_dict['safeBalance']) < int(value)+int(fee):
		response = { "errorMsg": "Invalid transaction: fund is not enough" }
		return jsonify(response), 401
	if bal_dict['duplicateTrans']:
		response = { "errorMsg": "Duplicate transaction!" }
		return jsonify(response), 402
	
	# Create a new transaction
	blockchain.append_transaction(transaction)
	response = { "transactionDataHash": transaction.TransactionDataHash }		
	return jsonify(response), 200

@app.route('/peers/notify-new-block', methods = ['POST'])
def notify_new_block():
	values = json.loads( request.data )
	print( "notify_new_block(): values = ", values )
	remote_host = values.get('nodeUrl')[7:]
	remote_difficulty = values.get('cumulativeDifficulty')
	own_difficulty = blockchain.getCumulativeDifficulty()
	if remote_difficulty>own_difficulty:
		thread = Thread(target = blockchain.synchronize_chain, args = (remote_host,))
		thread.start()	
	response = { "message": "Thank you for the notification." }
	code = 200
	return jsonify(response), code

@app.route('/peers/shakehands', methods = ['POST'])
def shakehands_peer():
	values = json.loads( request.data )
	print( "shakehands_peer(): values = ", values )
	remote_host = values.get('host')
	node_id = values.get('nodeId')
	thread = Thread(target = blockchain.add_peer, args = (node_id, remote_host))
	thread.start()	
	response = {
		"host": blockchain.Host,
		"nodeId": blockchain.nodeId
	}
	code = 200
	return jsonify(response), code

@app.route('/peers/connect', methods = ['POST'])
def connect_peer():
	print( "connect_peer(): request.data = ", request.data )
	values = json.loads( request.data )
	peer = values.get('peerUrl')
	if peer is None:
		response = {
			"errorMsg": "Please supply a valid peer"
		}
		code = 400
		return jsonify(response), code
	res = blockchain.register_peer(peer)
	if res==1:	
		response = {
			"errorMsg": "Already connected to peer: " + peer
		}
		code = 409
	elif res==2:
		response = {
			"errorMsg": "Failed to connect to peer: " + peer
		}
		code = 403
	else:
		response = {
			"message": "Connected to peer: " + peer		
		}
		code = 200
	return jsonify(response), code
	
@app.route('/nodes/resolve', methods = ['GET'])
def consensus():
	replaced = blockchain.resolve_conflict()
	blocks = json.dumps(blockchain.chain, default=lambda x: x.__dict__)
	transactions = json.dumps(blockchain.pending_transactions, default=lambda x: x.__dict__)
	
	if replaced:
		response = {
			'message' : 'Our chain was replaced',
			'new_chain' : blocks,
			'new_transactions' : transactions
		}
	else:
		response = {
			'message' : 'Our chain is authoritative',
			'chain' : blocks,
			'transactions' : transactions
		}
	return jsonify(response), 200

@app.route('/heartbeat', methods = ['GET'])
def procheartbeat():
	print( "Receive a heartbeat signal from a peer!" )
	response = {
		'message' : 'HeartBeat signal received!'
	}
	return jsonify(response), 200

@app.route("/peers", methods = ["GET"])
def disp_peers():
	peers_dict = dict()
	for peer in blockchain.nodes:
		peers_dict[peer.nodeId] = peer.URL
	return str(peers_dict), 200
	
@app.route("/info", methods = ["GET"])
def node_info():
	about = blockchain.About
	node_id = blockchain.nodeId
	chain_id = blockchain.chainId
	node_url = "http://" + blockchain.Host
	peers = len(blockchain.nodes)
	current_difficulty = blockchain.CurrentDifficulty
	block_count = len(blockchain.chain)
	cumulative_difficulty = current_difficulty * block_count
	confirmed_transactions_num = 0
	for i in range(len(blockchain.chain)):
		confirmed_transactions_num += len(blockchain.chain[i].Transactions)
	pending_transactions_num = len(blockchain.pending_transactions)
	response = {
		"about": about,
		"nodeId": node_id,
		"chainId": chain_id,
		"nodeUrl": node_url,
		"peers": peers,
		"currentDifficulty": current_difficulty,
		"blocksCount": block_count,
		"cumulativeDifficulty": cumulative_difficulty,
		"confirmedTransactions": confirmed_transactions_num,
		"pendingTransactions": pending_transactions_num
	}
	return jsonify(response), 200
	
@app.route("/debug/reset-chain", methods = ["GET"])
def reset_chain():
	global blockchain
	blockchain = BlockChain( host, blockchain_file, transaction_file, False )
	response = {
		"message": "The chain was reset to its genesis block"
	}
	return jsonify(response), 200
	
@app.route("/chain", methods = ["GET"])
def full_chain():
	blocks = json.dumps(blockchain.chain, default=lambda x: x.__dict__)
	transactions = json.dumps(blockchain.pending_transactions, default=lambda x: x.__dict__)
	chain_id = blockchain.chainId
	response = {
		'chain' : blocks,
		'chainId' : chain_id,
		'chain_difficulty' : blockchain.getCumulativeDifficulty(),
		'transactions' : transactions,
		'transaction_length' : len(blockchain.pending_transactions)
	}
	return jsonify(response), 200
	
@app.route('/blocks', methods = ['GET'])
def showAllBlocks():
	blocks = json.dumps(blockchain.chain, default=lambda x: x.__dict__)
	response = {
		'message' : 'All blocks data',
		'length' : len(blockchain.chain),
		'blocks' : blocks
	}
	return jsonify(response), 200

@app.route('/blocks/<block>', methods = ['GET'])
def showABlock(block):
	iBlock = int(block)
	blockdata = json.dumps(blockchain.chain[iBlock], default=lambda x: x.__dict__)
	response = {
		'message' : 'data of Block ' + block,
		'block' : blockdata
	}
	return jsonify(response), 200

@app.route('/transactions/pending', methods = ['GET'])
def display_pending_transactions():
	trans = json.dumps(blockchain.pending_transactions, default=lambda x: x.__dict__)
	response = {
		'message' : 'All pending transactions',
		'length' : len(blockchain.pending_transactions),
		'transactions' : trans 	
	}
	return jsonify(response), 200

@app.route('/transactions/confirmed', methods = ['GET'])
def display_confirmed_transactions():
	confirmed_transactions = []
	for i in range(len(blockchain.chain)):
		confirmed_transactions.extend(blockchain.chain[i].Transactions)
	trans = json.dumps(confirmed_transactions, default=lambda x: x.__dict__)
	response = {
		'message' : 'All confirmed transactions',
		'length' : len(confirmed_transactions), 
		'transactions' : trans
	}
	return jsonify(response), 200

@app.route('/transactions/<transhash>', methods = ['GET'])
def display_a_transaction(transhash):
	match = 0
	msg = "cannot find the transaction"
	for i in range(len(blockchain.chain)):
		for j in range(len(blockchain.chain[i].Transactions)):
			trans = blockchain.chain[i].Transactions[j]
			if trans.matchHash(transhash):
				match = 1
				msg = "Find the transaction from Block " + str(i)
				break
		if match > 0:
			break
	if not match:
		for k in range(len(blockchain.pending_transactions)):	
			trans = blockchain.pending_transactions[k]
			if trans.matchHash(transhash):
				match = 2
				msg = "Find the transaction from pending transaction list"
				break
	if match > 0:	
		transaction = json.dumps(trans, default=lambda x: x.__dict__)
		response = {
			'message': msg, 
			'transaction' : transaction
		}
	else:
		response = {
			'message': msg 
		}
	return jsonify(response), 200

@app.route('/address/<addr>/transactions', methods = ['GET'])
def show_addr_trans(addr):
	transactions = []
	for i in range(len(blockchain.chain)):
		for j in range(len(blockchain.chain[i].Transactions)):
			trans = blockchain.chain[i].Transactions[j]
			if trans.matchAddr(addr):
				transactions.append(trans)
	for k in range(len(blockchain.pending_transactions)):	
		trans = blockchain.pending_transactions[k]
		if trans.matchAddr(addr):
			transactions.append(trans)
	if len(transactions) > 0:	
		trans_json = json.dumps(transactions, default=lambda x: x.__dict__)
		response = {
			"address": addr, 
			"transactions": trans_json
		}
	else:
		response = {
			"address": addr,	
			"message": "Cannot find any transactions under the address" 
		}
	return jsonify(response), 200

@app.route('/address/<addr>/balance', methods = ['GET'])
def show_addr_balance(addr):
	if not BlockChain.valid_addr(addr):
		response = {
			"errorMsg": "Invalid address"
		}
		return jsonify(response), 404
	bal_dict = blockchain.checkBalanceHash(addr, "0") 	
	response = {
		"safeBalance": bal_dict["safeBalance"],
		"confirmedBalance": bal_dict["confirmedBalance"],
		"pendingBalance": bal_dict["pendingBalance"]
	}
	return jsonify(response), 200

@app.route('/balances', methods = ['GET'])
def showBalances():
	balance_dict = {
		"0000000000000000000000000000000000000000":0
	}
	Faucet_Account = blockchain.chain[0].Transactions[0].To
	for i in range(len(blockchain.chain)):
		for j in range(len(blockchain.chain[i].Transactions)):
			tran = blockchain.chain[i].Transactions[j]
			from_acct = tran.From
			to_acct = tran.To
			amount = int(tran.Value)
			fee = int(tran.Fee)
			if tran.TransferSuccessful:
				if from_acct in balance_dict:
					if from_acct!=Faucet_Account and to_acct!=Faucet_Account:
						balance_dict[from_acct] -= (amount+fee)
					else:	# Faucet transactions are waived from transaction fees
						balance_dict[from_acct] -= amount				
				else:
					if from_acct!=Faucet_Account and to_acct!=Faucet_Account:
						balance_dict[from_acct] = -(amount+fee)
					else:	# Faucet transactions are waived from transaction fees
						balance_dict[from_acct] = -amount				
				if to_acct in balance_dict:
					balance_dict[to_acct] += amount
				else:
					balance_dict[to_acct] = amount
			else:
				if from_acct in balance_dict:
					if from_acct!=Faucet_Account and to_acct!=Faucet_Account:
						balance_dict[from_acct] -= fee
				else:
					if from_acct!=Faucet_Account and to_acct!=Faucet_Account:
						balance_dict[from_acct] = -fee
	
	response = {
		'Accounts Number' : len(balance_dict), 
		'Balances' : balance_dict
	}
	return jsonify(response), 200

def HeartBeat():
	blockchain.doHeartBeat()

if __name__ == "__main__":
	from argparse import ArgumentParser
		
	parser = ArgumentParser()
	parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
	parser.add_argument('-l', '--load', default='Y', type=str, help='blockchain file to load')
	args = parser.parse_args()
	port = args.port
	host = "127.0.0.1:" + str(port)
	blockchain_file = "block_chain.txt"
	transaction_file = "transaction.txt"
	blockchain = None
	if args.load!="Y" or not os.path.isfile(blockchain_file):
		# Instance the BlockChain
		print("build blockchain from scratch")
		blockchain = BlockChain( host, blockchain_file, transaction_file, False )
	else:
		print("build blockchain by loading files" )
		blockchain = BlockChain( host, blockchain_file, transaction_file, True )
	rt = RepeatedTimer(30, HeartBeat)
	app.run(host='127.0.0.1', port=port, threaded=True)

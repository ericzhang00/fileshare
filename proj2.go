package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	FileMapping map[string]File
	SharedFileMapping map[string]ContentData
	PasswordKey []byte
	RSADecKey userlib.PKEDecKey
	DSPrivKey userlib.DSSignKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}
type File struct {
	ContentsUUID uuid.UUID
	SharingRecord map[string]uuid.UUID
}
type FileContents struct {
	Index int
	IndexToContent map[int]ContentData
}
type DataStoreContents struct {
	MAC []byte
	Contents []byte
}
type ContentData struct {
	UUID uuid.UUID
	MacK []byte
	EncK []byte
}
type SignatureMsg struct {
	Signature DataStoreContents
	Message []byte
}

var hashKey = []byte("0000000000000000")


//helper function for updating the user struct in the datastore
func (userdata *User) updateUserData() {
	//before storing data into the datastore, we need to encrypt and sign all data we are placing inside
	data, _ := json.Marshal(userdata)
	//encrypting password
	dataEncKey, _ := genHashKDFKey(userdata.PasswordKey, userdata.Username + "userstructEncryption", 32)
	dataMacKey, _ := genHashKDFKey(userdata.PasswordKey, userdata.Username + "userStructMAC", 32)

	dataEncrypted := userlib.SymEnc(dataEncKey, userlib.RandomBytes(16), data)
	dataMac, _ := userlib.HMACEval(dataMacKey, dataEncrypted)
	var dataWrapper DataStoreContents
	dataWrapper.MAC = dataMac
	dataWrapper.Contents = dataEncrypted
	dataOut, _ := json.Marshal(dataWrapper)

	//storing userdata in the datastore
	userdataKey, _ := genHashKDFKey(userdata.PasswordKey, "userdataKey", 16)
	userdataUUID, _ := uuid.FromBytes(userdataKey[:16])
	userlib.DatastoreSet(userdataUUID, dataOut)
}

func encryptMACandStore(dataEncryptionKey []byte, dataMACKey []byte, data []byte, UUID uuid.UUID) (err error) {
	dataEncrypted := userlib.SymEnc(dataEncryptionKey, userlib.RandomBytes(16), data)
	dataMAC, err := userlib.HMACEval(dataMACKey, dataEncrypted)
	if err != nil {
		return errors.New("error evaluating HMAC")
	}
	var filecontents DataStoreContents
	filecontents.Contents = dataEncrypted
	filecontents.MAC = dataMAC
	marshaled, err :=json.Marshal(filecontents)
	if err != nil {
		return errors.New("error marshaling contents")
	}
	userlib.DatastoreSet(UUID, marshaled)
	return nil
}

func verifyAndDecrypt(dataEncryptionKey []byte, dataMACKey []byte, UUID uuid.UUID) (data []byte, err error) {
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}

	//split the datastore values into the MAC and the data
	var filecontents DataStoreContents
	json.Unmarshal(packaged_data, &filecontents)
	MAC := filecontents.MAC
	data = filecontents.Contents

	//verify then decrypt
	actualMAC, _ := userlib.HMACEval(dataMACKey, data)
	ok = userlib.HMACEqual(MAC, actualMAC)
	if !ok {
		return nil, errors.New(strings.ToTitle("File has been tampered with"))
	}
	data = userlib.SymDec(dataEncryptionKey, data)
	return data, nil
}

func genHashKDFKey(key []byte, purpose string, length int) (data []byte, err error) {
	returnKey, err := userlib.HashKDF(key, []byte(purpose))
	if err != nil {
		return []byte(""), errors.New("error creating key")
	}
	return returnKey[:length], nil
}

func checkUsername(username string) (err error) {
	usernameListTemp, _ := genHashKDFKey([]byte("usernamelistEncryptionab"), "usernameListUUID", 16)
	usernameListUUID, _ := uuid.FromBytes(usernameListTemp)
	usernameListEncKey, _ := genHashKDFKey([]byte("usernamelistEncryptionab"), "usernameListEnc", 32)
	usernameListMacKey, _ := genHashKDFKey([]byte("usernamelistEncryptionab"), "usernameListMac", 32)
	usernameListMarshaled, err := verifyAndDecrypt(usernameListEncKey, usernameListMacKey, usernameListUUID)
	if err != nil {
		m := make (map[string]string)
		m[username] = username
		marshaledMap, err1 := json.Marshal(m)
		if err1 != nil {
			return errors.New("error marshaling map")
		}
		encryptMACandStore(usernameListEncKey, usernameListMacKey, marshaledMap, usernameListUUID)
		return nil
	}
	var usernameMap map[string]string
	json.Unmarshal(usernameListMarshaled, &usernameMap)
	_, ok:= usernameMap[username]
	if ok {
		return errors.New("Username already exists")
	}
	return nil
}
// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	err = checkUsername(username)
	if err != nil{
		return nil, err
	}


	//get public key
	RSAPubKey, RSADecKey, err1 := userlib.PKEKeyGen()
	if err1 != nil {
		return userdataptr, err1
	}
	DSPrivKey, DSPubKey, err2 := userlib.DSKeyGen()
	if err2 != nil {
		return userdataptr, err2
	}
	userlib.KeystoreSet(username, RSAPubKey)
	userlib.KeystoreSet(username + "sig", DSPubKey)
	userdata.RSADecKey = RSADecKey
	userdata.DSPrivKey = DSPrivKey

	//set username and password
	userdata.Username = username
	userdata.Password = password

	//use Argon2Key to generate a key based on the password with the username as salt
	//to be used for generating all keys
	passwordKey := userlib.Argon2Key([]byte(password + "password"), []byte(username + "username"), 32)
	userdata.PasswordKey = passwordKey

	userdata.FileMapping = make(map[string]File)
	userdata.SharedFileMapping = make(map[string]ContentData)

	//before storing data into the datastore, we need to encrypt and sign all data we are placing inside
	userdata.updateUserData()

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	passwordKey := userlib.Argon2Key([]byte(password + "password"), []byte(username + "username"), 32)

	userdataKey, _ := genHashKDFKey(passwordKey, "userdataKey", 16)
	userdataUUID, _ := uuid.FromBytes(userdataKey)

	dataEncKey, _ := genHashKDFKey(passwordKey, username + "userstructEncryption", 32)
	dataMacKey, _ := genHashKDFKey(passwordKey, username + "userStructMAC", 32)

	userstruct, err := verifyAndDecrypt(dataEncKey, dataMacKey, userdataUUID)
	if err != nil {
		return userdataptr, err
	}
	json.Unmarshal(userstruct, &userdata)
	if password != userdata.Password {
		return nil, errors.New(strings.ToTitle("Incorrect Password"))
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//calculate UUID for the file and marshal the data
	hashed,err := userlib.HMACEval(hashKey, append([]byte(filename + userdata.Username + userdata.Password), userlib.RandomBytes(32)...))
	if err != nil {
		return
	}
	UUID, err := uuid.FromBytes(hashed[:16])
	if err != nil {
		return
	}
	contentsUUID, err := uuid.FromBytes(hashed[16:32])
	if err != nil {
		return
	}
	packaged_data, err := json.Marshal(data)
	if err != nil {
		return
	}

	//generate keys for the fileContents and  using the user's passwordKey
	dataEncryptionKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryption", 32)
	if err != nil {
		return;
	}
	dataMACKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryptionMAC", 32)
	if err != nil {
		return
	}

	//generate keys for the actual file
	fileEncryptionKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + hex.EncodeToString(data) + hex.EncodeToString(userlib.RandomBytes(16)) + "encryption", 32)
	if err != nil {
		return;
	}
	fileMACKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + hex.EncodeToString(data) + hex.EncodeToString(userlib.RandomBytes(16)) + "MAC", 32)
	if err != nil {
		return
	}

	var uuidAndKeys ContentData
	uuidAndKeys.UUID = UUID
	uuidAndKeys.MacK = fileMACKey
	uuidAndKeys.EncK = fileEncryptionKey

	//use keys to encrypt and store the file (encrypt then authenticate)
	encryptMACandStore(fileEncryptionKey, fileMACKey, packaged_data, UUID)

	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))
	if err != nil {
		return
	}
	existingSharedFile, fileShared := userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)]
	existingFile, fileOwned := userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if fileOwned {
		existingContentsMarshaled, _:= verifyAndDecrypt(dataEncryptionKey, dataMACKey, existingFile.ContentsUUID)
		var existingContents FileContents
		err = json.Unmarshal(existingContentsMarshaled, &existingContents)
		if err != nil{
			return
		}
		existingContents.Index = 1
		existingContents.IndexToContent[existingContents.Index] = uuidAndKeys
		existingContents.Index += 1
		contentsMarshaled, err := json.Marshal(existingContents)
		if err != nil {
			return
		}

		//use keys to encrypt and store the contents (encrypt then authenticate)
		err = encryptMACandStore(dataEncryptionKey, dataMACKey, contentsMarshaled, existingFile.ContentsUUID)
		if err != nil {
			return
		}
		return
	} else if fileShared {
		existingSharedStruct, _:= verifyAndDecrypt(existingSharedFile.EncK, existingSharedFile.MacK, existingSharedFile.UUID)
		var contentsData ContentData
		json.Unmarshal(existingSharedStruct, &contentsData)
		existingContentsMarshaled, _ := verifyAndDecrypt(contentsData.EncK, contentsData.MacK, contentsData.UUID)
		var existingContents FileContents
		err = json.Unmarshal(existingContentsMarshaled, &existingContents)
		if err != nil{
			return
		}
		existingContents.Index = 1
		existingContents.IndexToContent[existingContents.Index] = uuidAndKeys
		existingContents.Index += 1
		contentsMarshaled, err := json.Marshal(existingContents)
		if err != nil {
			return
		}

		//use keys to encrypt and store the contents (encrypt then authenticate)
		err = encryptMACandStore(contentsData.EncK, contentsData.MacK, contentsMarshaled, contentsData.UUID)
		if err != nil {
			return
		}
		return
	}


	//initialize and store the FileContents struct that contains mappings from index to uuid into the datastore, encrypted with the dataencryption and dataMAC keys
	var contents FileContents
	contents.Index = 1
	contents.IndexToContent = make(map[int]ContentData)
	contents.IndexToContent[contents.Index] = uuidAndKeys
	contents.Index += 1
	contentsMarshaled, err := json.Marshal(contents)
	if err != nil {
		return
	}

	//use keys to encrypt and store the file (encrypt then authenticate)
	err = encryptMACandStore(dataEncryptionKey, dataMACKey, contentsMarshaled, contentsUUID)
	if err != nil {
		return
	}

	//put the filename and contents uuid into the fileList mapping and update the user struct in the datastore
	var file File
	file.ContentsUUID = contentsUUID
	file.SharingRecord = make(map[string]uuid.UUID)
	hashedFileName, err = userlib.HMACEval(hashKey, []byte(filename))
	if err != nil {
		return
	}
	userdata.FileMapping[hex.EncodeToString(hashedFileName)] = file
	userdata.updateUserData()

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var contentsUUID uuid.UUID
	var dataEncryptionKey []byte
	var dataMACKey []byte
	var contents FileContents
	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))
	file, ok:= userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if !ok {
		td, ok := userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)]
		if !ok {
			return errors.New("file to append to does not exist")
		}

		fileDataMarshaled, _ := userlib.DatastoreGet(td.UUID)

		//fileData is encrypted and MAC'd using the symmetric keys stored in td so we decrypt it using those
		var fileDataEncrypted DataStoreContents
		json.Unmarshal(fileDataMarshaled, &fileDataEncrypted)

		actualMAC, _ := userlib.HMACEval(td.MacK, fileDataEncrypted.Contents)
		ok = userlib.HMACEqual(fileDataEncrypted.MAC, actualMAC)
		if !ok {
			return errors.New(strings.ToTitle("File Data has been tampered with"))
		}
		fileDataDecrypted := userlib.SymDec(td.EncK, fileDataEncrypted.Contents)

		//we then unmarshal and store the fileData into a ContentData struct to get the UUID and keys
		var fileData ContentData
		json.Unmarshal(fileDataDecrypted, &fileData)
		dataEncryptionKey = fileData.EncK
		dataMACKey = fileData.MacK
		contentsUUID = fileData.UUID
	} else {
		contentsUUID = file.ContentsUUID
		dataEncryptionKey, _ = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryption", 32)
		dataMACKey, _ = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryptionMAC", 32)
	}

	contentsMarshaled, _ := verifyAndDecrypt(dataEncryptionKey, dataMACKey, contentsUUID)
	json.Unmarshal(contentsMarshaled, &contents)

	hashed,_ := userlib.HMACEval(hashKey, append(append([]byte(filename + userdata.Username + userdata.Password), data...),userlib.RandomBytes(16)...))
	UUID, _ := uuid.FromBytes(hashed[:16])
	//generate keys for the actual file
	fileEncryptionKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + hex.EncodeToString(data) + hex.EncodeToString(userlib.RandomBytes(16)) + "encryption", 32)
	if err != nil {
		return;
	}
	fileMACKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + hex.EncodeToString(data) + hex.EncodeToString(userlib.RandomBytes(16)) + "MAC", 32)
	if err != nil {
		return
	}
	encryptMACandStore(fileEncryptionKey, fileMACKey, data, UUID)

	var uuidAndKeys ContentData
	uuidAndKeys.UUID = UUID
	uuidAndKeys.EncK = fileEncryptionKey
	uuidAndKeys.MacK = fileMACKey
	contents.IndexToContent[contents.Index] = uuidAndKeys
	contents.Index += 1

	contentsReMarshaled, _ := json.Marshal(contents)
	encryptMACandStore(dataEncryptionKey, dataMACKey, contentsReMarshaled, contentsUUID)
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	//calculate UUID for the file and retrieve it from the datastore
	var ok bool
	//var UUID uuid.UUID
	var dataEncryptionKey []byte
	var dataMACKey []byte
	var contents FileContents
	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))

	file, ok :=userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if !ok {
		td, ok2 := userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)]
		if !ok2 {
			return []byte(""), errors.New("File does not exist")
		}
		fileDataMarshaled, _ := userlib.DatastoreGet(td.UUID)

		//fileData is encrypted and MAC'd using the symmetric keys stored in td so we decrypt it using those
		var fileDataEncrypted DataStoreContents
		json.Unmarshal(fileDataMarshaled, &fileDataEncrypted)

		actualMAC, _ := userlib.HMACEval(td.MacK, fileDataEncrypted.Contents)
		ok = userlib.HMACEqual(fileDataEncrypted.MAC, actualMAC)
		if !ok {
			return nil, errors.New(strings.ToTitle("File Data has been tampered with"))
		}
		fileDataDecrypted := userlib.SymDec(td.EncK, fileDataEncrypted.Contents)

		//we then unmarshal and store the fileData into a ContentData struct to get the UUID and keys
		var fileData ContentData
		json.Unmarshal(fileDataDecrypted, &fileData)
		dataEncryptionKey = fileData.EncK
		dataMACKey = fileData.MacK
		contentsMarshaled, err := verifyAndDecrypt(dataEncryptionKey, dataMACKey, fileData.UUID)
		if err != nil {
			return []byte(""), err
		}
		json.Unmarshal(contentsMarshaled, &contents)
	} else {
		dataEncryptionKey, _ = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryption", 32)
		dataMACKey, _ = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryptionMAC", 32)
		contentsMarshaled, err := verifyAndDecrypt(dataEncryptionKey, dataMACKey,file.ContentsUUID)
		if err != nil {
			return []byte(""), err
		}
		json.Unmarshal(contentsMarshaled, &contents)
	}

	//iterate through whole index to uuid mapping and decrypt and verify every piece of the file and add it to the returnData byte array
	var returnData []byte
	for i := 1; i < contents.Index; i++ {
		data, err := verifyAndDecrypt(contents.IndexToContent[i].EncK, contents.IndexToContent[i].MacK, contents.IndexToContent[i].UUID)
		if err != nil {
			return []byte(""), err
		}
		//unmarshal the data and return it
		json.Unmarshal(data, &data)
		returnData = append(returnData, data...)
	}

	return returnData, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	//declare variables used both for shared files and owned files
	var td ContentData
	var tokenEncryptionKey []byte
	var tokenMACKey []byte
	//get information for access token
	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))

	fileStruct, ok := userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if !ok {
		td, ok = userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)]
		if !ok {
			return "", errors.New("file does not exist");
		}
		tokenMACKey = td.MacK
		tokenEncryptionKey = td.EncK
	} else {
		dataEncryptionKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryption", 32)
		if err != nil {
			return "", errors.New("error creating encryption key")
		}
		dataMACKey, err := genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryptionMAC", 32)
		if err != nil {
			return "", errors.New("error creating MAC key")
		}

		//store it into a struct for marshaling
		var file ContentData
		file.UUID = fileStruct.ContentsUUID
		file.EncK = dataEncryptionKey
		file.MacK = dataMACKey

		//generate symmetric keys for encrypting the fileData inside the datastore
		tokenEncryptionKey, err = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "encryptionToken", 16)
		if err != nil {
			return "", errors.New("error creating token encryption key")
		}
		tokenMACKey, err = genHashKDFKey(userdata.PasswordKey, filename + userdata.Password + userdata.Username + "macToken", 16)
		if err != nil {
			return "", errors.New("error creating token MAC key")
		}

		//generate UUID for storing the encrypted file info
		temp, _ := genHashKDFKey(userdata.PasswordKey, filename + recipient, 16)
		sharedUUID, _ := uuid.FromBytes(temp)

		//marshal data and encrypt and MAC using tokenKeys for storing in the datastore
		marshaled, _ := json.Marshal(file)
		err = encryptMACandStore(tokenEncryptionKey, tokenMACKey, marshaled, sharedUUID)
		if err != nil {
			return "", err
		}

		//store the sharedUUID inside the fileMapping
		fileStruct.SharingRecord[recipient] = sharedUUID
		userdata.updateUserData()

		td.UUID = sharedUUID
		td.MacK = tokenMACKey
		td.EncK = tokenEncryptionKey
	}

	tdMarshaled , _ := json.Marshal(td)

	//sign and encrypt the access_token data
	//actual token data is encrypted using PKE
	//signature is encrypted using symmetric keys - both SymEnc and HMAC
	//both are stored inside the SigMsg struct and sent to the receiver

	//signature generated and encrypted using symmetric keys
	signedUUID, err3 := userlib.DSSign(userdata.DSPrivKey, tdMarshaled)
	if err3 != nil {
		return "", err3
	}

	if (len(tokenEncryptionKey) == 0) {
		return "", errors.New("token encryption key length 0")
	}
	signatureEncrypted := userlib.SymEnc(tokenEncryptionKey, userlib.RandomBytes(16), signedUUID)
	signatureMAC, err := userlib.HMACEval(tokenMACKey, signatureEncrypted)
	if err != nil {
		return "", errors.New("problem with hmaceval")
	}
	var signature DataStoreContents
	signature.Contents = signatureEncrypted
	signature.MAC = signatureMAC

	//access token encrypted using PKEEnc with recipient's public key
	recipientPK, ok:= userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("error getting the recipient's public key from the keystore")
	}
	encryptedTD, err := userlib.PKEEnc(recipientPK, tdMarshaled)
	if err != nil {
		return "", err
	}

	//wrap encrypted access token and signature in sigMSG struct, marshal, and return
	var sigMsg SignatureMsg
	sigMsg.Signature = signature
	sigMsg.Message = encryptedTD
	sigMsgMarshaled, err := json.Marshal(sigMsg)
	if err != nil {
		return "", errors.New("error marshaling sigMSG struct")
	}

	return string(sigMsgMarshaled), nil
	}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
//TODO Be sure that your code works even with multiple instances of the same user.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	//unmarshal the magic_string
	var sigMsg SignatureMsg
	json.Unmarshal([]byte(magic_string), &sigMsg)

	//decrypt and unmarshal the access token data
	decryptedTDMarshaled, err := userlib.PKEDec(userdata.RSADecKey, sigMsg.Message)
	if err != nil {
		return err
	}
	var td ContentData
	json.Unmarshal(decryptedTDMarshaled, &td)

	//decrypt the signature and check HMAC
	actualMAC, _ := userlib.HMACEval(td.MacK, sigMsg.Signature.Contents)
	if !userlib.HMACEqual(sigMsg.Signature.MAC, actualMAC) {
		return errors.New("file signature has been tampered with")
	}
	signature := userlib.SymDec(td.EncK, sigMsg.Signature.Contents)

	//verify the signature
	senderDSPK, ok := userlib.KeystoreGet(sender + "sig")
	if !ok {
		return errors.New(strings.ToTitle("error getting sender signature PK from keystore"))
	}
	err = userlib.DSVerify(senderDSPK, decryptedTDMarshaled, signature)
	if err != nil {
		return err
	}

	//store the access token in the sharedFileMapping
	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))
	_, ok =  userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if ok {
		return errors.New("File with the same name already exists")
	}
	_, ok = userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)]
	if ok {
		return errors.New("File with the same name already exists")
	}

	userdata.SharedFileMapping[hex.EncodeToString(hashedFileName)] = td
	userdata.updateUserData()

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	hashedFileName, err := userlib.HMACEval(hashKey, []byte(filename))

	fileStruct, ok:= userdata.FileMapping[hex.EncodeToString(hashedFileName)]
	if !ok {
		return errors.New("file does not exist")
	}
	UUID, ok := fileStruct.SharingRecord[target_username]
	if !ok {
		return errors.New("user to revoke either does not exist or does not have access")
	}
	userlib.DatastoreSet(UUID, []byte(""))
	return
}

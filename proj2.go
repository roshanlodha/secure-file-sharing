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
	Files []uuid.UUID
	Shared map[string]uuid.UUID //filename||recipient --> accessUUID
	UserUUID uuid.UUID
	SaltedPassword []byte
	DecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
}

type File struct {
	FileData []byte
	NextEdit uuid.UUID
	FinalEdit uuid.UUID
}

type FileToken struct {
	NextHop uuid.UUID
	LastHop bool //
	FileKey []byte //Enc(Pk, SymKey)
	HashedName [64]byte //HASH filename
	Created bool
}

// Helper function to handle multiple user instances.
func RefreshUser(username string, saltedPassword []byte) (userdataptr *User, err error) {
	var userdata User

	//generate user's unique ID via Hash(username)
	hashedUsername := userlib.Hash([]byte(username))
	if len(hashedUsername) < 16 { //checks if username is empty
		return nil, errors.New("Username must not be empty!")
	}
	//use random data to get len of mac
	randomMAC, _ := userlib.HMACEval(userlib.RandomBytes(16), []byte("whyisthisprojectsohard"))

	//retrieve user struct
	temp, _ := uuid.FromBytes(hashedUsername[:16])
	encryptedMACedUser, ok := userlib.DatastoreGet(temp)
	if (!ok) || (len(encryptedMACedUser) <= len(randomMAC)) {
		return nil, errors.New("User not found or corrupted!")
	}

	//generate a (deterministic) keys to decrypt and Verify User
	usersymkey, _ := userlib.HashKDF(saltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(saltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//seperate user struct from MAC
	encyptedUser := encryptedMACedUser[:len(encryptedMACedUser)-64]
	/*
	userMAC := encryptedMACedUser[len(encryptedMACedUser)-64:]

	//verify user
	MACencryptedUser, _ := userlib.HMACEval(usermackey, encyptedUser)
	if !userlib.HMACEqual(MACencryptedUser, userMAC) {
		return nil, errors.New("User data corrupted!")
	}

	//decrypt user and unmarshal at userdataptr
	*/
	decryptedUser := userlib.SymDec(usersymkey, encyptedUser)
	json.Unmarshal(decryptedUser, &userdata)

	return &userdata, nil
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
	var EncKey userlib.PKEEncKey
	var VerifyKey userlib.DSVerifyKey

	//generate user's unique ID via Hash(username)
	hashedUsername := userlib.Hash([]byte(username))
	if len(hashedUsername) < 16 { //checks if username is empty
		return nil, errors.New("Username must not be empty!")
	}

	//store unique UUID
	userdata.UserUUID, _ = uuid.FromBytes(hashedUsername[:16])
	_, ok := userlib.DatastoreGet(userdata.UserUUID)
	if ok {
		return nil, errors.New("User already exists!")
	}

	//store username and salted password (username is the salt)
	userdata.Username = username
	userdata.SaltedPassword = userlib.Argon2Key([]byte(password), []byte(username), 16)

	//initialize empty map for sharing
	userdata.Shared = make(map[string]uuid.UUID)

	//generate and store RSA Enc, Dec keys	
	EncKey, userdata.DecKey, _ = userlib.PKEKeyGen()
	_ = userlib.KeystoreSet(username+"enc", EncKey)

	//generate and store RSA Sign, Verify keys	
	userdata.SignKey, VerifyKey, _ = userlib.DSKeyGen()
	_ = userlib.KeystoreSet(username+"ver", VerifyKey)

	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, usermackey)
	encryptedMACedUser := append(encyptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//generate user's unique ID via Hash(username)
	hashedUsername := userlib.Hash([]byte(username))
	if len(hashedUsername) < 16 { //checks if username is empty
		return nil, errors.New("Username must not be empty!")
	}
	//use random data to get len of mac
	randomMAC, _ := userlib.HMACEval(userlib.RandomBytes(16), []byte("whyisthisprojectsohard"))

	//retrieve user struct
	temp, _ := uuid.FromBytes(hashedUsername[:16])
	encryptedMACedUser, ok := userlib.DatastoreGet(temp)
	if (!ok) || (len(encryptedMACedUser) <= len(randomMAC)) {
		return nil, errors.New("User not found or corrupted!")
	}

	//generate salted password to generate keys via HKDF and to check pwd match
	saltedPassword := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//generate a (deterministic) keys to decrypt and Verify User
	usersymkey, _ := userlib.HashKDF(saltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(saltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//seperate user struct from MAC
	encyptedUser := encryptedMACedUser[:len(encryptedMACedUser)-64]
	/*
	userMAC := encryptedMACedUser[len(encryptedMACedUser)-64:]

	//verify user
	MACencryptedUser, _ := userlib.HMACEval(usermackey, encyptedUser)
	if !userlib.HMACEqual(MACencryptedUser, userMAC) {
		return nil, errors.New("User data corrupted!")
	}

	//decrypt user and unmarshal at userdataptr
	*/
	decryptedUser := userlib.SymDec(usersymkey, encyptedUser)
	json.Unmarshal(decryptedUser, &userdata)

	//check password
	if string(saltedPassword) != string(userdata.SaltedPassword) {
		return nil, errors.New("Incorrect password!")
	}

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//refresh user
	userdataptr, _ := RefreshUser(userdata.Username, userdata.SaltedPassword)
	*userdata = *userdataptr

	var myToken FileToken
	var file File
	var exists bool

	for _, fileUUID := range userdata.Files {
		marshalledToken, _ := userlib.DatastoreGet(fileUUID)
		json.Unmarshal(marshalledToken, &myToken)
		if userlib.Hash([]byte(filename)) == myToken.HashedName {
			exists = true
			//check if file creator
			if !myToken.Created {
				return
			} else {
				//key = Enc(PKreceiver, Dec(SkMe, key))
				key, _ := userlib.PKEDec(userdata.DecKey, myToken.FileKey)
				mackey, _ := userlib.HashKDF(key, []byte("mac"))
				mackey = mackey[:16]

				//encrypt and mac filedata
				encryptedData := userlib.SymEnc(key, userlib.RandomBytes(16), data)
				dataMAC, _ := userlib.HMACEval(mackey, encryptedData)
				encryptedMACedData := append(encryptedData, dataMAC...)

				//build file
				file.FileData = encryptedMACedData
				file.NextEdit, _ = uuid.FromBytes([]byte("NullUUID"))
				file.FinalEdit, _ = uuid.FromBytes([]byte("NullUUID"))

				//encrypt and mac file
				marshaledFile, _ := json.Marshal(file)
				encryptedFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledFile)
				fileMAC, _ := userlib.HMACEval(mackey, encryptedFile)
				encryptedMACedFile := append(encryptedFile, fileMAC...)

				//overwrite file in datastore
				userlib.DatastoreSet(myToken.NextHop, encryptedMACedFile)

				//update User struct in datastore
				//generate a (deterministic) keys to encrypt and MAC User
				usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
				usersymkey = usersymkey[:16]
				usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
				usermackey = usermackey[:16]

				//marshall user 
				marshalledUser, _ := json.Marshal(userdata)

				//encrypt and mac user struct
				encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
				userMAC, _ := userlib.HMACEval(usermackey, usermackey)
				encryptedMACedUser := append(encyptedUser, userMAC...)

				//set in datastore
				userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)
				
				return
			}
		}
	}
	if !exists {
		//if file not found
		//use HKDF to generate symmetric encryption and mac keys
		key := userlib.RandomBytes(16)
		mackey, _ := userlib.HashKDF(key, []byte("mac"))
		mackey = mackey[:16]

		//encrypt and mac filedata
		encryptedData := userlib.SymEnc(key, userlib.RandomBytes(16), data)
		dataMAC, _ := userlib.HMACEval(mackey, encryptedData)
		encryptedMACedData := append(encryptedData, dataMAC...)

		//build file
		file.FileData = encryptedMACedData
		file.NextEdit, _ = uuid.FromBytes([]byte("NullUUID"))
		file.FinalEdit, _ = uuid.FromBytes([]byte("NullUUID"))

		//encrypt and mac file
		marshaledFile, _ := json.Marshal(file)
		encryptedFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledFile)
		fileMAC, _ := userlib.HMACEval(mackey, encryptedFile)
		encryptedMACedFile := append(encryptedFile, fileMAC...)

		//set in datastore
		fileUUID := uuid.New()
		userlib.DatastoreSet(fileUUID, encryptedMACedFile)

		//create an access token for myself and store
		myToken.NextHop = fileUUID
		myToken.LastHop = true
		myToken.HashedName = userlib.Hash([]byte(filename))
		myToken.Created = true

		//get my encryption key
		myEncKey, _ := userlib.KeystoreGet(userdata.Username+"enc")
		myToken.FileKey, _ = userlib.PKEEnc(myEncKey, key)

		//add token to Datastore
		tokenUUID := uuid.New()

		marshalledToken, _ := json.Marshal(myToken)
		userlib.DatastoreSet(tokenUUID, marshalledToken)

		//add token to files table
		userdata.Files = append(userdata.Files, tokenUUID)

		//update User struct in datastore
		//generate a (deterministic) keys to encrypt and MAC User
		usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
		usersymkey = usersymkey[:16]
		usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
		usermackey = usermackey[:16]

		//marshall user 
		marshalledUser, _ := json.Marshal(userdata)

		//encrypt and mac user struct
		encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
		userMAC, _ := userlib.HMACEval(usermackey, usermackey)
		encryptedMACedUser := append(encyptedUser, userMAC...)

		//set in datastore
		userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)
	}

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//refresh user
	userdataptr, refresherror := RefreshUser(userdata.Username, userdata.SaltedPassword)
	if refresherror != nil {
		return errors.New("RefreshingError!")
	}
	*userdata = *userdataptr

	var found bool
	var key []byte
	var myToken FileToken
	var baseFile File
	var accessUUID uuid.UUID
	var edit File
	var previousFinal File

	//find file and extract key
	for _, fileUUID := range userdata.Files {
		marshalledToken, _ := userlib.DatastoreGet(fileUUID)
		json.Unmarshal(marshalledToken, &myToken)
		if myToken.HashedName == userlib.Hash([]byte(filename)) {
			//get key and generate FileStruct decryption key
			key, _ = userlib.PKEDec(userdata.DecKey, myToken.FileKey)

			//get to the final hop and set accessUUID
			for !myToken.LastHop {
				marshalledFileToken, ok := userlib.DatastoreGet(myToken.NextHop)
				if !ok {
					return errors.New(strings.ToTitle("Parent's file access revoked!"))	
				}
				json.Unmarshal(marshalledFileToken, &myToken)
			}
			//get accessUUID 
			accessUUID = myToken.NextHop
			encryptedMACedFile, _ := userlib.DatastoreGet(myToken.NextHop)
			encryptedFile := encryptedMACedFile[:len(encryptedMACedFile)-64]

			//decrypt and unmarshal
			marshalledFile := userlib.SymDec(key, encryptedFile)
			json.Unmarshal(marshalledFile, &baseFile)

			found = true
		}
	}

	//check if file exists
	if !found {
		return errors.New(strings.ToTitle("File does not exist with this user!"))
	}

	//nullUUID for checking edits 
	nullUUID, _ := uuid.FromBytes([]byte("NullUUID"))
	//editUUID for the edit
	editUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))

	//should have baseFile and key
	mackey, _ := userlib.HashKDF(key, []byte("mac"))
	mackey = mackey[:16]

	//encrypt and mac filedata
	encryptedData := userlib.SymEnc(key, userlib.RandomBytes(16), data)
	dataMAC, _ := userlib.HMACEval(mackey, encryptedData)
	encryptedMACedData := append(encryptedData, dataMAC...)

	//build file
	edit.FileData = encryptedMACedData
	edit.NextEdit = nullUUID
	edit.FinalEdit = nullUUID

	//encrypt and mac file
	marshaledFile, _ := json.Marshal(edit)
	encryptedFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledFile)
	fileMAC, _ := userlib.HMACEval(mackey, encryptedFile)
	encryptedMACedFile := append(encryptedFile, fileMAC...)

	userlib.DatastoreSet(editUUID, encryptedMACedFile)

	//if first edit 
	if baseFile.FinalEdit == nullUUID {
		baseFile.NextEdit = editUUID
		baseFile.FinalEdit = editUUID

		//encrypt and mac file
		marshaledBaseFile, _ := json.Marshal(baseFile)
		encryptedBaseFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledBaseFile)
		baseFileMAC, _ := userlib.HMACEval(mackey, encryptedBaseFile)
		encryptedMACedBaseFile := append(encryptedBaseFile, baseFileMAC...)
		
		//set in datastore
		userlib.DatastoreSet(accessUUID, encryptedMACedBaseFile)
	} else { 
		//else, also update previous final
		encryptedMACedPreviousFinal, _ := userlib.DatastoreGet(baseFile.FinalEdit)
		if len(encryptedMACedPreviousFinal) < 64 {
			return errors.New(strings.ToTitle("File corrupted!"))
		}
		encryptedPreviousFinal := encryptedMACedPreviousFinal[:len(encryptedMACedPreviousFinal)-64]

		//decrypt and unmarshal
		marshalledPreviousFinal := userlib.SymDec(key, encryptedPreviousFinal)
		json.Unmarshal(marshalledPreviousFinal, &previousFinal)
		previousFinal.NextEdit = editUUID

		//encrypt and mac file
		marshalledPreviousFinal, _ = json.Marshal(previousFinal)
		encryptedPreviousFinal = userlib.SymEnc(key, userlib.RandomBytes(16), marshalledPreviousFinal)
		previousFinalMAC, _ := userlib.HMACEval(mackey, encryptedPreviousFinal)
		encryptedMACedPreviousFinal = append(encryptedPreviousFinal, previousFinalMAC...)

		//set in datastore
		userlib.DatastoreSet(baseFile.FinalEdit, encryptedMACedPreviousFinal)

		//update basefile 
		baseFile.FinalEdit = editUUID

		//encrypt and mac file
		marshaledBaseFile, _ := json.Marshal(baseFile)
		encryptedBaseFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledBaseFile)
		baseFileMAC, _ := userlib.HMACEval(mackey, encryptedBaseFile)
		encryptedMACedBaseFile := append(encryptedBaseFile, baseFileMAC...)
		
		//set in datastore
		userlib.DatastoreSet(accessUUID, encryptedMACedBaseFile)
	}

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	//refresh user
	userdataptr, refresherror := RefreshUser(userdata.Username, userdata.SaltedPassword)
	if refresherror != nil {
		return nil, errors.New("RefreshingError!")
	}
	*userdata = *userdataptr

	var found bool
	var key []byte
	var myToken FileToken
	var baseFile File
	var accessUUID uuid.UUID

	//find file and extract key
	for _, fileUUID := range userdata.Files {
		marshalledToken, _ := userlib.DatastoreGet(fileUUID)
		json.Unmarshal(marshalledToken, &myToken)
		if myToken.HashedName == userlib.Hash([]byte(filename)) {
			//get key and generate FileStruct decryption key
			key, _ = userlib.PKEDec(userdata.DecKey, myToken.FileKey)
			if len(key) == 0 {
				return nil, errors.New(strings.ToTitle("Unable to get key!"))
			}

			//get to the final hop and set accessUUID
			for !myToken.LastHop {
				marshalledFileToken, ok := userlib.DatastoreGet(myToken.NextHop)
				if !ok {
					return nil, errors.New(strings.ToTitle("Parent's file access revoked!"))
				}
				json.Unmarshal(marshalledFileToken, &myToken)
			}
			//get accessUUID 
			accessUUID = myToken.NextHop
			encryptedMACedFile, _ := userlib.DatastoreGet(accessUUID)
			encryptedFile := encryptedMACedFile[:len(encryptedMACedFile)-64]

			//decrypt and unmarshal file
			marshalledFile := userlib.SymDec(key, encryptedFile)
			json.Unmarshal(marshalledFile, &baseFile)

			//decrypt and unmarshal data
			encryptedMACedData := baseFile.FileData
			encryptedData := encryptedMACedData[:len(encryptedMACedData)-64]
			data = userlib.SymDec(key, encryptedData)

			//set next edit accessUUID
			accessUUID = baseFile.NextEdit

			found = true
			break
		}
	}

	//check if file exists
	if !found {
		return nil, errors.New(strings.ToTitle("File does not exist with this user!"))
	}

	nullUUID, _ := uuid.FromBytes([]byte("NullUUID"))
	for accessUUID != nullUUID {
		encryptedMACedFile, _ := userlib.DatastoreGet(accessUUID)
		encryptedFile := encryptedMACedFile[:len(encryptedMACedFile)-64]

		//decrypt and unmarshal file
		marshalledFile := userlib.SymDec(key, encryptedFile)
		json.Unmarshal(marshalledFile, &baseFile)

		//decrypt and unmarshal data
		encryptedMACedData := baseFile.FileData
		encryptedData := encryptedMACedData[:len(encryptedMACedData)-64]
		data = append(data, userlib.SymDec(key, encryptedData)...)

		//set next edit accessUUID
		accessUUID = baseFile.NextEdit
	}

	return data, nil
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
	//refresh user
	userdataptr, refresherror := RefreshUser(userdata.Username, userdata.SaltedPassword)
	if refresherror != nil {
		return "", errors.New("RefreshingError!")
	}
	*userdata = *userdataptr

	//relavent info
	var myToken FileToken
	var sendingToken FileToken
	var found bool

	//search through all my files to find my access token
	for _, fileUUID := range userdata.Files {
		marshalledToken, _ := userlib.DatastoreGet(fileUUID)
		json.Unmarshal(marshalledToken, &myToken)
		if userlib.Hash([]byte(filename)) == myToken.HashedName {
			found = true

			//set nextHop to my fileUUID, lastHop is false
			sendingToken.NextHop = fileUUID
			sendingToken.LastHop = false

			//reciever is NOT creator of file
			sendingToken.Created = false

			//key = Enc(PKreceiver, Dec(SkMe, key))
			key, _ := userlib.PKEDec(userdata.DecKey, myToken.FileKey)
			receiverKey, ok := userlib.KeystoreGet(recipient + "enc")
			if !ok {
				return "", errors.New(strings.ToTitle("Recipient not found!"))
			}
			sendingToken.FileKey, _ = userlib.PKEEnc(receiverKey, key)

			break
		}
	}

	if !found {
		return "", errors.New(strings.ToTitle("File not found!"))
	}

	//create an accessUUID from Bytes to store sendingFile 
	accessBytes := userlib.RandomBytes(16)
	accessUUID, _ := uuid.FromBytes(accessBytes)

	//sign accesskey
	signature, _ := userlib.DSSign(userdata.SignKey, accessBytes)
	magic_string = string(append(accessBytes, signature...))

	//marshal and store token in datastore
	marshalledToken, _ := json.Marshal(sendingToken)
	userlib.DatastoreSet(accessUUID, marshalledToken)

	//add the shared instance to Shared (for later revocation)
	userdata.Shared[filename+recipient] = accessUUID

	//update User struct in datastore
	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, usermackey)
	encryptedMACedUser := append(encyptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return magic_string, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	var myToken FileToken

	//generate file's hashedFilename
	hashedFilename := userlib.Hash([]byte(filename))

	//extract accessToken and signature
	if len(magic_string) < 16 {
		return errors.New(strings.ToTitle("Access token corrupted!"))
	}
	accessBytes := []byte(magic_string)[:16]
	accessUUID, _ := uuid.FromBytes(accessBytes)

	//check if file already shared with user
	for _, f := range userdata.Files {
		fileToken, ok := userlib.DatastoreGet(f)
		json.Unmarshal(fileToken, &myToken)
		if !ok {
			return errors.New(strings.ToTitle("FileToken not found!"))
		}
		if (myToken.HashedName == hashedFilename) {
			return errors.New(strings.ToTitle("File already shared!"))
		}
	}

	//TODO: validate signature
	signature := []byte(magic_string)[16:]
	verKey, ok := userlib.KeystoreGet(sender+"ver")
	if !ok {
		return errors.New(strings.ToTitle("Sender not found!"))
	} else if userlib.DSVerify(verKey, accessBytes, signature) != nil {

	}

	//unmarshal token
	marshalledToken, ok := userlib.DatastoreGet(accessUUID)
	if !ok {
		return errors.New(strings.ToTitle("Access token corrupted!"))
	}
	json.Unmarshal(marshalledToken, &myToken)

	//update Files
	userdata.Files = append(userdata.Files, accessUUID)

	//update filename
	myToken.HashedName = userlib.Hash([]byte(filename))

	//reset in DataStore
	marshalledToken, _ = json.Marshal(myToken)
	userlib.DatastoreSet(accessUUID, marshalledToken)

	//update User struct in datastore
	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, usermackey)
	encryptedMACedUser := append(encyptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	//get UUID to remove
	accessUUID, ok := userdata.Shared[filename+target_username]
	if !ok {
		return errors.New(strings.ToTitle("Invalid filename and target combo!"))
	}

	//remove from shared table
	delete(userdata.Shared, filename+target_username)
	
	//removes from datastore
	userlib.DatastoreDelete(accessUUID)

	//update User struct in datastore
	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encyptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, usermackey)
	encryptedMACedUser := append(encyptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return
}

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
	SaltedPassword []byte
	UserUUID uuid.UUID
	DecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	Created []CreatedFile
	Shared []SharedFile
	Received []ReceivedFile
	Sign []byte
}

type CreatedFile struct {
	FileUUID uuid.UUID
	FileKey []byte
	FileName string
}

type SharedFile struct {
	MagicString string
	Recipient string
	TokenSign []byte
}

type ReceivedFile struct {
	FileKey []byte
	FileName string
	AccessUUID uuid.UUID
}

type Share struct {
	NextHop uuid.UUID
	Key []byte
	FinalHop bool
}

type File struct {
	FileData []byte
	Creator string
	NextEdit uuid.UUID
	FinalEdit uuid.UUID
	ContentSign []byte
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

	var EncKey userlib.PKEEncKey
	var VerifyKey userlib.DSVerifyKey

	var userID uuid.UUID

	//generate user's unique ID via Hash(username)
	hashedUsername := userlib.Hash([]byte(username))
	if len(hashedUsername) < 16 { //checks if username is empty
		return nil, errors.New("Username must not be empty!")
	}

	userID, err = uuid.FromBytes(hashedUsername[:16])
	_, ok := userlib.DatastoreGet(userID)
	if ok {
		return &userdata, errors.New("User with this username already exists!")
	}

	userdata.Username = username
	userdata.SaltedPassword = userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.UserUUID = userID
	
	//generate and store RSA Enc, Dec keys	
	EncKey, userdata.DecKey, _ = userlib.PKEKeyGen()
	_ = userlib.KeystoreSet(username+"enc", EncKey)

	//generate and store RSA Sign, Verify keys	
	userdata.SignKey, VerifyKey, _ = userlib.DSKeyGen()
	_ = userlib.KeystoreSet(username+"ver", VerifyKey)

	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))

	usersymkey = usersymkey[:16]
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encryptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, encryptedUser)
	encryptedMACedUser := append(encryptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//compute user UUID and see if user is in datastore
	hashedUsername := userlib.Hash([]byte(username))
	userID, err := uuid.FromBytes(hashedUsername[:16])
	encryptedMACedUser, ok := userlib.DatastoreGet(userID)

	//use random data to get len of mac
	randomMAC, _ := userlib.HMACEval(userlib.RandomBytes(16), []byte("whyisthisprojectsohard"))

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
	encryptedUser := encryptedMACedUser[:len(encryptedMACedUser)-64]
	
	userMAC := encryptedMACedUser[len(encryptedMACedUser)-64:]
	
	//verify user
	MACencryptedUser, _ := userlib.HMACEval(usermackey, encryptedUser)
	if !userlib.HMACEqual(MACencryptedUser, userMAC) {
		return nil, errors.New("User data corrupted!")
	}
	
	//decrypt user and unmarshal at userdataptr
	decryptedUser := userlib.SymDec(usersymkey, encryptedUser)
	json.Unmarshal(decryptedUser, &userdata)

	//check password
	if string(saltedPassword) != string(userdata.SaltedPassword) {
		return nil, errors.New("Incorrect password!")
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	var file File
	key := userlib.RandomBytes(16)
	var overwrite bool

	//update userdata
	//refreshedUserData, _ := userlib.DatastoreGet(userdata.UserUUID)
	//json.Unmarshal(refreshedUserData, &userdata) 

	//hash filename||username for confidentiality and file UUID
	hashedFileID := userlib.Hash([]byte(filename + userdata.Username))
	fileUUID, _ := uuid.FromBytes([]byte(hashedFileID[:16]))

	//check if file already exists
	for _, file := range userdata.Created {
		if file.FileName == filename {
			overwrite = true
			key = file.FileKey
		}
	}

	//check if file already exists
	for _, file := range userdata.Received {
		if file.FileName == filename {
			overwrite = true
			key = file.FileKey
		}
	}

	mackey, _ := userlib.HashKDF(key, []byte("mac"))
	mackey = mackey[:16]

	//build and marshall File
	file.FileData = userlib.SymEnc(key, userlib.RandomBytes(16), data)
	file.NextEdit, _ = uuid.FromBytes([]byte("nullUUID"))
	file.FinalEdit, _ = uuid.FromBytes([]byte("nullUUID"))

	//encrypt and mac file
	marshaledFile, _ := json.Marshal(file)
	encryptedFile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledFile)
	fileMAC, _ := userlib.HMACEval(mackey, encryptedFile)
	encryptedMACedFile := append(encryptedFile, fileMAC...)

	//add file to datastore
	userlib.DatastoreSet(fileUUID, encryptedMACedFile)

	//add file metadata to CreatedFile instance
	if !overwrite {
		metadata := CreatedFile{fileUUID, key, filename}
		userdata.Created = append(userdata.Created, metadata)
	}

	//update User struct in datastore
	//generate a (deterministic) keys to encrypt and MAC User
	usersymkey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("enc"))
	usersymkey = usersymkey[:16]
	usermackey, _ := userlib.HashKDF(userdata.SaltedPassword, []byte("mac"))
	usermackey = usermackey[:16]

	//marshall user 
	marshalledUser, _ := json.Marshal(userdata)

	//encrypt and mac user struct
	encryptedUser := userlib.SymEnc(usersymkey, userlib.RandomBytes(16), marshalledUser)
	userMAC, _ := userlib.HMACEval(usermackey, usermackey)
	encryptedMACedUser := append(encryptedUser, userMAC...)

	//set in datastore
	userlib.DatastoreSet(userdata.UserUUID, encryptedMACedUser)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	
	var found bool
	var prevFile File
	var OGfile File
	var file File
	var key []byte
	var fileUUID uuid.UUID

	//UUID for the new edit
	editID, _ := uuid.FromBytes(userlib.RandomBytes(16))

	//get key for shared file if creator
	for _, file := range userdata.Created {
		if file.FileName == filename {
			key = file.FileKey
			found = true
		}
	}

	//get key for shared file if shared with me
	for _, file := range userdata.Received {
		if file.FileName == filename {
			key = file.FileKey
			found = true
		}
	}

	//check if file exists
	if !found {
		return errors.New(strings.ToTitle("File does not exist with this user!"))
	}

	//build and marshall File
	file.FileData = userlib.SymEnc(key, userlib.RandomBytes(16), data)
	file.NextEdit, _ = uuid.FromBytes([]byte("nullUUID"))
	file.FinalEdit, _ = uuid.FromBytes([]byte("nullUUID"))

	//encrypt and mac file
	marshaledFile, _ := json.Marshal(file)

	//add file to datastore
	userlib.DatastoreSet(editID, marshaledFile)


	//look for file in created table
	for _, createdfile := range userdata.Created {
		if createdfile.FileName == filename {
			key = createdfile.FileKey 
			fileUUID = createdfile.FileUUID

			break
		}
	}

	//look in received table if not in created
	for _, receivedfile := range userdata.Received {
		if receivedfile.FileName == filename {
			var share Share
			key = receivedfile.FileKey 
			shareUUID := receivedfile.AccessUUID

			//if file has been shared with us, get loading data
			marshalledShare, ok := userlib.DatastoreGet(shareUUID)
			if !ok {
				return errors.New(strings.ToTitle("File access revoked!"))	
			}
			json.Unmarshal(marshalledShare, &share)

			//get to the final hop and set fileUUID
			for !share.FinalHop {
				marshalledShare, ok = userlib.DatastoreGet(share.NextHop)
				if !ok {
					return errors.New(strings.ToTitle("Parent's file access revoked!"))	
				}
				json.Unmarshal(marshalledShare, &share)
			}
			fileUUID = share.NextHop
			
			break
		}
	}

	//unmarshall file and decrypt FileD
	encryptedMACedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New(strings.ToTitle("File not found!"))
	}
	if len(key) == 0 {
		return errors.New(strings.ToTitle("Unknown key error."))
	}

	encryptedFile := encryptedMACedFile[:len(encryptedMACedFile)-64]

	//decrypt and unmarshal file
	marshalledFile := userlib.SymDec(key, encryptedFile)
	json.Unmarshal(marshalledFile, &OGfile)

	nullUUID, _ := uuid.FromBytes([]byte("nullUUID"))
	prevfinalID := OGfile.FinalEdit

	//if this is the first edit, update the NextEdit
	if prevfinalID == nullUUID {
		OGfile.NextEdit = editID
		OGfile.FinalEdit = editID

		mackey, _ := userlib.HashKDF(key, []byte("mac"))
		mackey = mackey[:16]

		//encrypt and mac file
		marshaledOGfile, _ := json.Marshal(OGfile)
		encryptedOGfile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledOGfile)
		ogfileMAC, _ := userlib.HMACEval(mackey, encryptedOGfile)
		encryptedMACedOGFile := append(encryptedOGfile, ogfileMAC...)

		//add file to datastore
		userlib.DatastoreSet(fileUUID, encryptedMACedOGFile)

	} else {


		//unmarshall file and decrypt FileData
		marshalledPrevFile, ok := userlib.DatastoreGet(prevfinalID)
		if !ok {
			return errors.New(strings.ToTitle("File not found!"))
		}
		if len(key) == 0 {
			return errors.New(strings.ToTitle("Unknown key error."))
		}

		json.Unmarshal(marshalledPrevFile, &prevFile)


		prevFile.NextEdit = editID

		//encrypt and mac file
		marshaledPrevfile, _ := json.Marshal(prevFile)
		userlib.DatastoreSet(prevfinalID, marshaledPrevfile)

		OGfile.FinalEdit = editID

		mackey, _ := userlib.HashKDF(key, []byte("mac"))
		mackey = mackey[:16]

		//encrypt and mac file
		marshaledOGfile, _ := json.Marshal(OGfile)
		encryptedOGfile := userlib.SymEnc(key, userlib.RandomBytes(16), marshaledOGfile)
		ogfileMAC, _ := userlib.HMACEval(mackey, encryptedOGfile)
		encryptedMACedOGFile := append(encryptedOGfile, ogfileMAC...)

		//add file to datastore
		userlib.DatastoreSet(fileUUID, encryptedMACedOGFile)

	}

	return err

}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	
	var key []byte
	var fileUUID uuid.UUID
	var file File
	//var created bool
	///var received bool

	//update userdata
	//refreshedUserData, _ := userlib.DatastoreGet(userdata.UserUUID)
	//json.Unmarshal(refreshedUserData, &userdata) 

	//look for file in created table
	for _, createdfile := range userdata.Created {

		if createdfile.FileName == filename {
			key = createdfile.FileKey 
			fileUUID = createdfile.FileUUID
			//created = true

			break
		}
	}

	//look in received table if not in created
	for _, receivedfile := range userdata.Received {
		if receivedfile.FileName == filename {
			//received = true
			var share Share
			key = receivedfile.FileKey 
			shareUUID := receivedfile.AccessUUID

			//if file has been shared with us, get loading data
			marshalledShare, ok := userlib.DatastoreGet(shareUUID)
			if !ok {
				return nil, errors.New(strings.ToTitle("File access revoked!"))	
			}
			json.Unmarshal(marshalledShare, &share)

			//get to the final hop and set fileUUID
			for !share.FinalHop {
				marshalledShare, ok = userlib.DatastoreGet(share.NextHop)
				if !ok {
					return nil, errors.New(strings.ToTitle("Parent's file access revoked!"))	
				}
				json.Unmarshal(marshalledShare, &share)
			}
			fileUUID = share.NextHop
			break
		}
	}


	//unmarshall file and decrypt FileData
	encryptedMACedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	if len(key) == 0 {
		return nil, errors.New(strings.ToTitle("Unknown key error."))
	}

	encryptedFile := encryptedMACedFile[:len(encryptedMACedFile)-64]
	fileMAC := encryptedMACedFile[len(encryptedMACedFile)-64:]

	//decrypt and unmarshal file
	marshalledFile := userlib.SymDec(key, encryptedFile)
	json.Unmarshal(marshalledFile, &file)


	mackey, _ := userlib.HashKDF(key, []byte("mac"))
	mackey = mackey[:16]
	
	//verify user
	MACencryptedFile, _ := userlib.HMACEval(mackey, encryptedFile)
	if !userlib.HMACEqual(MACencryptedFile, fileMAC) {
		return nil, errors.New("File data corrupted!")
	}


	if(len(file.FileData)) == 0 {
		return nil, errors.New(strings.ToTitle("Empty file!"))
	}
	data = append(data, userlib.SymDec(key, file.FileData)...)

	
	//load data from next edits
	nullUUID, _ := uuid.FromBytes([]byte("nullUUID"))
	for file.NextEdit != nullUUID {
		packaged_data, _ := userlib.DatastoreGet(file.NextEdit)
		json.Unmarshal(packaged_data, &file)
		data = append(data, userlib.SymDec(key, file.FileData)...)
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

	//update userdata
	//refreshedUserData, _ := userlib.DatastoreGet(userdata.UserUUID)
	//json.Unmarshal(refreshedUserData, &userdata) 	

	magic_string = string(userlib.RandomBytes(16))
	var ss Share
	var sf SharedFile
	var key []byte
	var found bool

	//check if recipient exists
	hashedRecipient := userlib.Hash([]byte(recipient))
	recipientID, err := uuid.FromBytes(hashedRecipient[:16])
	_, ok := userlib.DatastoreGet(recipientID)
	if !ok {
		return "", errors.New(strings.ToTitle("Recipient does not exist!"))
	}

	//hash filename||username for confidentiality and file UUID
	hashedFileID := userlib.Hash([]byte(filename + userdata.Username))
	UUID, _ := uuid.FromBytes([]byte(hashedFileID[:16]))

	//get key for shared file if creator
	for _, file := range userdata.Created {
		if file.FileName == filename {
			key = file.FileKey
			found = true
			ss.FinalHop = true
			ss.NextHop = UUID
		}
	}

	//get key for shared file if shared with me
	for _, file := range userdata.Received {
		if file.FileName == filename {
			key = file.FileKey
			found = true
			ss.NextHop = file.AccessUUID
		}
	}

	//check if file exists
	if !found {
		return "", errors.New(strings.ToTitle("File does not exist with this user!"))
	}


	//create new Share Struct with encrypted file data
	recipientPubKey, _ := userlib.KeystoreGet(recipient+"enc")
	ss.Key, _ = userlib.PKEEnc(recipientPubKey, key)

	//add share struct to datastore
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))
	metadata, _ := json.Marshal(ss)
	userlib.DatastoreSet(accessUUID, metadata)

	//create new SharedFile and add to sharer's Shared table
	sf.MagicString = magic_string
	sf.Recipient = recipient + filename
	//sf.TokenSign, _ = userlib.DSSign(userdata.SignKey, []byte(sf.MagicString)) 
	userdata.Shared = append(userdata.Shared, sf)

	//update User struct in Datastore
	//marshallUserData, _ := json.Marshal(userdata)
	//userlib.DatastoreSet(userdata.UserUUID, marshallUserData)

	return magic_string, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	//update userdata
	//refreshedUserData, _ := userlib.DatastoreGet(userdata.UserUUID)
	//json.Unmarshal(refreshedUserData, &userdata) 
		
	var receivedfile ReceivedFile
	var share Share
	//var senderUser User
	//var sign []byte


	//check if file already shared
	for _, file := range userdata.Received {
		if file.FileName == filename {
			return errors.New(strings.ToTitle("File already shared!"))
		}
	}

	//check if file already shared
	for _, file := range userdata.Created {
		if file.FileName == filename {
			return errors.New(strings.ToTitle("You already have a file with this name!"))
		}
	}

	//create accessUUID for magic string
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))

	//extract and store key
	marshalledShare, _ := userlib.DatastoreGet(accessUUID)
	json.Unmarshal(marshalledShare, &share)

	/*
	//if verify key does not exist, error
	verKey, ok := userlib.KeystoreGet(sender + "verify")
	if !ok {
		return errors.New("verify key does not exist")
	}

	temp := userlib.Hash([]byte(sender))
	userID, _ := uuid.FromBytes(temp[:16])
	senderStruct, ok := userlib.DatastoreGet(userID)
	if !ok {
		return errors.New("sender does not exist")
	}

	json.Unmarshal(senderStruct, &senderUser)

	//get signature of magic string
	for _, file := range senderUser.Shared {
		if string(file.MagicString) == string(magic_string) {
			sign = file.TokenSign
		}
	}


	//check if access token actually sent by sender
	tokErr := userlib.DSVerify(verKey, []byte(magic_string), sign)
	if tokErr != nil {
		return errors.New("filedata tampered with")
	}
	*/

	receivedfile.FileKey, _ = userlib.PKEDec(userdata.DecKey, share.Key)

	//add filename and accessUUID and store file "token"
	receivedfile.FileName = filename
	receivedfile.AccessUUID = accessUUID
	userdata.Received = append(userdata.Received, receivedfile)

	//update User struct in Datastore
	//marshallUserData, _ := json.Marshal(userdata)
	//userlib.DatastoreSet(userdata.UserUUID, marshallUserData)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	var target string
	var magic_string string
	var creator bool
	var found bool

	for _, cf := range userdata.Created {
		if cf.FileName == filename {
			creator = true
		}
	}

	if !creator {
		return errors.New(strings.ToTitle("Tried to revoke access for file user did not create"))
	}


	target = target_username + filename

	for _, t := range userdata.Shared {
		if t.Recipient == target {
			magic_string = t.MagicString
			found = true
			break
		}
	}

	if !found {
		return errors.New(strings.ToTitle("You didn't share this file with this user!"))
	}
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))
	userlib.DatastoreDelete(accessUUID)

	//find index of token in Shared
	var deletionindex int
	for i, token := range userdata.Shared {
		if token.MagicString == magic_string {
			deletionindex = i
		}
	}
	//delete from Shared table
	userdata.Shared[deletionindex] = userdata.Shared[len(userdata.Shared)-1]
	userdata.Shared = userdata.Shared[:len(userdata.Shared)-1]

	//update User struct in Datastore
	//marshallUserData, _ := json.Marshal(userdata)
	//userlib.DatastoreSet(userdata.UserUUID, marshallUserData)

	return err

}
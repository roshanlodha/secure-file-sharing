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
	Userkey []byte
	DecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	Created []CreatedFile
	Shared []Tokens
	All []SharedWithMe

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type CreatedFile struct {
	fileUUID uuid.UUID
	fileKey []byte
}

type Tokens struct {
	Recipient string
	Token string
}

type SharedWithMe struct {
	shareUUID uuid.UUID
	NextHop string
}

type Share struct {
	Creator uuid.UUID
	NextHop uuid.UUID
	Key []byte
}

type File struct {
	FileData []byte
	Creator string
	NextEdit uuid.UUID
	FinalEdit uuid.UUID
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
	var userinfo []byte

	userdata.Username = username
	userdata.Userkey = userlib.Argon2Key([]byte(password), []byte(username), 32)
	
	EncKey, userdata.DecKey, err = userlib.PKEKeyGen()
	err = userlib.KeystoreSet(username+"enc", EncKey)

	userdata.SignKey, VerifyKey, err = userlib.DSKeyGen()
	err = userlib.KeystoreSet(username+"verify", VerifyKey)

	temp := userlib.Hash([]byte(username))
	userID, err = uuid.FromBytes(temp[:16])
	userinfo, err = json.Marshal(userdata)
	userlib.DatastoreSet(userID, userinfo)
	//End of toy implementation

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	
	var userdata User
	var userID uuid.UUID
	var userStruct []byte
	var userKeyPrime []byte
	var ok bool

	userdataptr = &userdata

	temp := userlib.Hash([]byte(username))
	userID, err = uuid.FromBytes(temp[:16])
	userStruct, ok = userlib.DatastoreGet(userID)

	if !ok {
		return userdataptr, err
	}

	json.Unmarshal(userStruct, &userdataptr)
	userKeyPrime = userlib.Argon2Key([]byte(password), []byte(username), 32)

	if string(userKeyPrime) != string(userdata.Userkey) {
		return userdataptr, err
	}

	//No integrity check right now
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	var file File

	key := userlib.RandomBytes(16)
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])

	file.FileData = userlib.SymEnc(key, userlib.RandomBytes(16), data)
	packaged_data, _ := json.Marshal(file)

	userlib.DatastoreSet(UUID, packaged_data)

	metadata := CreatedFile{UUID, key}
	userdata.Created = append(userdata.Created, metadata)
	//End of toy implementation

	return
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var tempFile File
	var edit File
	var key []byte
	editUUID := uuid.New()

	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	for _, file := range userdata.Created {
		if file.fileUUID == UUID {
			key = file.fileKey //TODO: update keyfinder for shared users
		}
	}

	//create and store edit 
	edit.FileData = userlib.SymEnc(key, userlib.RandomBytes(16), data)
	packaged_data, _ := json.Marshal(edit)
	userlib.DatastoreSet(editUUID, packaged_data)
	
	//update previous final
	packaged_data, _ = userlib.DatastoreGet(UUID)
	json.Unmarshal(packaged_data, &tempFile)
	packaged_data, _ = userlib.DatastoreGet(tempFile.FinalEdit) //old final
	json.Unmarshal(packaged_data, &tempFile) 
	tempFile.NextEdit = editUUID //previous final --> new edit

	//update original
	packaged_data, _ = userlib.DatastoreGet(UUID)
	json.Unmarshal(packaged_data, &tempFile)
	tempFile.FinalEdit = editUUID

	return
}


// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	var file File
	var key []byte
	var created bool

	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	for _, file := range userdata.Created { //TODO: write KeyFinder helper
		if file.fileUUID == UUID {
			key = file.fileKey 
			created = true
		}
	}

	//shared handling
	if !created {
		var temp SharedWithMe
		for _, sharedfile := range userdata.All { //TODO: write KeyFinder helper
			if sharedfile.shareUUID == UUID {
				temp = file
			}
		}
		
	}
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}

	json.Unmarshal(packaged_data, &file)
	data = userlib.SymDec(key, file.FileData)
	return data, nil
	//End of toy implementation

	return
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

	var key []byte
	var token Share
	magic_string = string(userlib.RandomBytes(16))

	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	for _, file := range userdata.Created { //replace with keyfinder
		if file.fileUUID == UUID {
			key = file.fileKey
		}
	}

	//create accestoken as Share Struct 
	childEncKey, ok := userlib.KeystoreGet(recipient+"enc")
	if !ok {
		return "", errors.New(strings.ToTitle("Recipient does not exist!"))
	}
	token.NextHop = UUID
	token.Key, _ = userlib.PKEEnc(childEncKey, key)

	//store token in datastore and return address
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))
	temp, _ := json.Marshal(token)
	userlib.DatastoreSet(accessUUID, temp)
	userdata.Shared = append(userdata.Shared, Tokens{recipient, magic_string})

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	var token SharedWithMe
	token.NextHop = magic_string
	token.shareUUID, _ = uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	userdata.All = append(userdata.All, token)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}


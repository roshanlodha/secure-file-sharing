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
	Shared []SharedFile
	Received []ReceivedFile
}

type CreatedFile struct {
	FileUUID uuid.UUID
	FileKey []byte
	FileName string
}

type SharedFile struct {
	MagicString string
	Recipient string
}

type ReceivedFile struct {
	FileKey []byte
	FileName string
	AccessUUID uuid.UUID
}

type Share struct {
	Creator uuid.UUID
	NextHop uuid.UUID
	Key []byte
	FinalHop bool
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
	userdataptr = &userdata

	//compute user UUID and see if user is in datastore
	temp := userlib.Hash([]byte(username))
	userID, err := uuid.FromBytes(temp[:16])
	userStruct, ok := userlib.DatastoreGet(userID)

	//if user does not exist, error
	if !ok {
		err = errors.New("user does not exist")
		return userdataptr, err
	}

	//unmarshal user struct and compute salted hashed password
	json.Unmarshal(userStruct, &userdataptr)
	userKeyPrime := userlib.Argon2Key([]byte(password), []byte(username), 32)

	//if passwords do not match, error
	if string(userKeyPrime) != string(userdata.Userkey) {
		err = errors.New("passwords do not match")
		return userdataptr, err
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

	//hash filename||username for confidentiality and file UUID
	hashedFileID := userlib.Hash([]byte(filename + userdata.Username))
	fileUUID, _ := uuid.FromBytes([]byte(hashedFileID[:16]))

	//build and marshall File
	file.FileData = userlib.SymEnc(key, userlib.RandomBytes(16), data)
	packaged_data, _ := json.Marshal(file)

	//add file to datastore
	userlib.DatastoreSet(fileUUID, packaged_data)

	//add file metadata to CreatedFile instance
	metadata := CreatedFile{fileUUID, key, filename}
	userdata.Created = append(userdata.Created, metadata)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	
	var key []byte
	var fileUUID uuid.UUID
	var file File

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
				return nil, errors.New(strings.ToTitle("File access revoked!"))	
			}
			json.Unmarshal(marshalledShare, &share)

			//get to the final hop and set fileUUID
			for !share.FinalHop {
				fileUUID = share.NextHop
				marshalledShare, ok = userlib.DatastoreGet(share.NextHop)
				if !ok {
					return nil, errors.New(strings.ToTitle("File access revoked!"))	
				}
				json.Unmarshal(marshalledShare, &share)
			}
			fileUUID = share.NextHop
			
			break
		}
	}

	//should have fileUUID and key now
	packaged_data, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}

	//unmarshall file and decrypt FileData
	json.Unmarshal(packaged_data, &file)
	data = userlib.SymDec(key, file.FileData)

	return data, nil
	//End of toy implementation

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
		if file.FileUUID == UUID {
			key = file.FileKey
			found = true
			ss.FinalHop = true
		}
	}

	//get key for shared file if shared with me
	for _, file := range userdata.Received {
		if file.AccessUUID == UUID {
			key = file.FileKey
			found = true
		}
	}

	//check if file exists
	if !found {
		return "", errors.New(strings.ToTitle("File does not exist with this user!"))
	}


	//create new Share Struct with encrypted file data
	hashedUserName := userlib.Hash([]byte(userdata.Username))
	ss.Creator, _ = uuid.FromBytes(hashedUserName[:16])
	ss.NextHop = UUID
	recipientPubKey, _ := userlib.KeystoreGet(recipient+"enc")
	ss.Key, _ = userlib.PKEEnc(recipientPubKey, key)

	//add share struct to datastore
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))
	metadata, _ := json.Marshal(ss)
	userlib.DatastoreSet(accessUUID, metadata)

	//create new SharedFile and add to sharer's Shared table
	sf.MagicString = magic_string
	sf.Recipient = recipient + filename
	userdata.Shared = append(userdata.Shared, sf)

	return magic_string, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
		
	var receivedfile ReceivedFile
	var share Share

	//create accessUUID for magic string
	accessUUID, _ := uuid.FromBytes([]byte(magic_string))

	//extract and store key
	marshalledShare, _ := userlib.DatastoreGet(accessUUID)
	json.Unmarshal(marshalledShare, &share)
	receivedfile.FileKey, _ = userlib.PKEDec(userdata.DecKey, share.Key)

	//add filename and accessUUID and store file "token"
	receivedfile.FileName = filename
	receivedfile.AccessUUID = accessUUID
	userdata.Received = append(userdata.Received, receivedfile)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}

// Package security
// @Author: Jianming Que
// @Description:
// @Version: 1.0.0
// @Date: 2021/1/31 4:10 下午
// @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
//
package keychain

import (
	"crypto/rand"
	"fmt"
	"minlib/component"
	"minlib/minsecurity/identity"
	"minlib/packet"
)

const defaultIdentityName = "/localhost/operator"

// KeyChain
// 用于给网络包签名和验签
//
// @Description:
//	1. 请调用 CreateKeyChain 方法创建一个 KeyChain 指针，或者创建一个 KeyChain 结构体后，手动调用 InitialKeyChain 进行初始化
//
type KeyChain struct {
	IdentityManager                    // 内嵌身份管理器
	currentIdentity *identity.Identity // 当前使用的身份
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
///// 构造函数 Create*
/////////////////////////////////////////////////////////////////////////////////////////////////////////

// CreateKeyChain
// 创建并初始化一个KeyChain对象
//
// @Description:
// @return *identity.Identity
// @return error
//
func CreateKeyChain() (*KeyChain, error) {
	var keyChain KeyChain
	return &keyChain, keyChain.InitialKeyChain()
}

// InitialKeyChain 使用默认存储路径初始化
//
// @Description:
// @receiver k
// @return error
//
func (k *KeyChain) InitialKeyChain() error {
	return k.InitialKeyChainByPath(DefaultIdentityDBPath)
}

// InitialKeyChainByPath
// 初始化 KeyChain
//
// @Description:
// @receiver k
// @return error
//
func (k *KeyChain) InitialKeyChainByPath(path string) error {
	// 初始化 IdentityManager
	if err := k.IdentityManager.InitByPath(path); err != nil {
		return err
	}

	// 指定当前使用默认的网络身份
	k.currentIdentity = k.IdentityManager.defaultIdentity

	// TODO: 考虑是否需要在没有默认身份的时候创建一个缺省的本地网络身份
	// 如果没有默认的身份，则创建一个缺省的默认身份
	if k.currentIdentity == nil {
		defaultIdentity := k.IdentityManager.GetIdentityByName(defaultIdentityName)

		// 如果只是因为没有设定默认身份，且之前创建过 defaultIdentityName 对应的身份，则直接使用它
		if defaultIdentity != nil {
			k.currentIdentity = defaultIdentity
		} else {
			// 创建一个默认的不加密的网络身份
			newIdentity, err := k.IdentityManager.CreateIdentityByName(defaultIdentityName, "", path, dbFile)
			if err != nil {
				return err
			}
			if _, err := k.IdentityManager.SetDefaultIdentity(newIdentity, path, dbFile); err != nil {
				return err
			}
			k.currentIdentity = newIdentity
		}
	}

	return nil
}

// SetCurrentIdentity
// 设置当前使用的网络身份
//
// @Description:
//	1.
// @receiver k
// @param identity
// @param password
//
func (k *KeyChain) SetCurrentIdentity(identity *identity.Identity, password string) error {
	// 这边用 password 对目标网络身份进行解锁，调用 identity.UnLock(password)
	if password != "" && identity.IsLocked() {
		if ok, err := identity.UnLock(password, k.IdentityManager.privateKeyEncryptionAlgorithm); err != nil {
			return err
		} else if !ok {
			return KeyChainError{
				msg: "Unlock " + identity.Name + " by " + password + " failed!!",
			}
		}
	}
	k.currentIdentity = identity
	return nil
}

// GetCurrentIdentity 获取当前使用的网络身份
//
// @Description:
// @receiver k
// @param identity
// @return *identity.Identity
//
func (k *KeyChain) GetCurrentIdentity() *identity.Identity {
	return k.currentIdentity
}

// GenerateCertificationForIdentity
// 为一个网络身份申请证书
//
// @Description:
// @receiver k
// @param identity
// @param force
// @return error
//
func (k *KeyChain) GenerateCertificationForIdentity(identity *identity.Identity, force bool) error {
	// TODO: 这边应该发起网络通信，向 MIS 请求给这个网络身份签发一个证书，留待 MIR 完成后进行补充
	return nil
}

//
// 检查一个网络身份是否可用
//
// @Description:
//	1. 首先检查 identity 是否为空；
//	2. 接着检查 identity 是否包含私钥；
//	3. 接着检查 identify 是否被锁定
// @param identity
// @return error
//
func checkIdentityCanUseToSign(identity *identity.Identity) error {
	// 首先检查 identity 是否为空
	if identity == nil {
		return KeyChainError{msg: fmt.Sprintf(
			"Identity is nil!")}
	}

	// 检查是否存在私钥（如果该身份只是用来验签的，则很可能只包含公钥和证书）
	if !identity.HashPrivateKey() {
		return KeyChainError{msg: fmt.Sprintf(
			"Identity not have Private key, so can't use to sign!")}
	}

	// 检查秘钥是否已经解锁，如果处于被锁定的状态，则不能用于签名
	if identity.IsLocked() {
		return KeyChainError{msg: fmt.Sprintf(
			"Identity is locked, so can't use to sign")}
	}

	// 返回空表示通过验证，可以用来签名
	return nil
}

//
// 从 MIN 网络包中提取出标识区和只读区的值，用于签名和验签
//
// @Description:
// @param packet
//
func getIdentifierAndReadOnlyValueFromPacket(packet *packet.MINPacket) ([]byte, error) {
	// 将标识区和只读区的 Value 读取出来进行签名
	identifierBlock, err := packet.IdentifierField.SelfWireEncode(&packet.IdentifierField)
	if err != nil {
		return nil, err
	}
	readOnlyBlock, err := packet.ReadOnlyField.SelfWireEncode(&packet.ReadOnlyField)
	if err != nil {
		return nil, err
	}

	rawData := make([]byte, len(identifierBlock.GetValue())+len(readOnlyBlock.GetValue()))
	copy(rawData, identifierBlock.GetValue())
	copy(rawData[len(identifierBlock.GetValue()):], readOnlyBlock.GetValue())
	return rawData, nil
}

// Sign
// 给一个通用的网络包进行签名
//
// @Description:
// @receiver k
// @param packet
//
func (k *KeyChain) Sign(packet *packet.MINPacket) error {
	// 首先检查当前使用的身份是否可以用来签名
	if err := checkIdentityCanUseToSign(k.currentIdentity); err != nil {
		return err
	}

	// 提取标识区和只读区的值，对其进行签名
	rawData, err := getIdentifierAndReadOnlyValueFromPacket(packet)
	if err != nil {
		return err
	}

	// 对标识区和只读区进行签名
	signResult, err := k.currentIdentity.Sign(rand.Reader, rawData, nil)
	if err != nil {
		return err
	}

	// 往包中添加签名
	signature, err := component.CreateSignatureByIdentityAndValue(k.currentIdentity, signResult)
	if err != nil {
		return err
	}

	// TODO: 这边直接给通过 addSignature 的方式存在问题，应该定义标识区的固定位置存储特定含义的标识
	packet.AddSignature(signature)
	return nil
}

// SignCPacket
// 对 CPacket 进行签名
//
// @Description:
// @receiver k
// @param cPacket
//
func (k *KeyChain) SignCPacket(cPacket *packet.CPacket) error {
	if err := cPacket.FillDataToFields(); err != nil {
		return err
	}
	return k.Sign(&cPacket.MINPacket)
}

// SignInterest
// 对 Interest 进行签名
//
// @Description:
// @receiver k
// @param interest
//
func (k *KeyChain) SignInterest(interest *packet.Interest) error {
	if err := interest.FillDataToFields(); err != nil {
		return err
	}
	return k.Sign(&interest.MINPacket)
}

// SignData
// 对 Data 进行签名
//
// @Description:
// @receiver k
// @param mgmt_data
//
func (k *KeyChain) SignData(data *packet.Data) error {
	if err := data.FillDataToFields(); err != nil {
		return err
	}
	return k.Sign(&data.MINPacket)
}

// Verify
// 验证一个MIN网络包中的签名是否有效
//
// @Description:
// @receiver k
// @param signature
// @return error
//
func (k *KeyChain) Verify(minPacket *packet.MINPacket) error {
	// 提取签名区的第一个签名进行验证（认为签名区的第一个签名为包的签名，包含标识区和只读区签名）
	signature, err := minPacket.GetSignature(0)
	if err != nil {
		return err
	}

	// 首先提取 signature 中签名者的网络身份信息，并根据它在本地查询是否有对应的网络身份
	identifyName := signature.SigInfo.GetKeyLocator().GetIdentifier().ToUri()
	verifyIdentity := k.IdentityManager.GetIdentityByName(identifyName)

	// 如果在本地没有找到对应的网络身份，则验签失败
	if verifyIdentity == nil {
		return KeyChainError{msg: fmt.Sprintf(
			"Verify failed, could not found the identity, which name is %s", identifyName)}
	}

	// 提取标识区和只读区的值，使用其进行验签
	rawData, err := getIdentifierAndReadOnlyValueFromPacket(minPacket)

	// 验证包的签名是否合法
	_, err = verifyIdentity.Verify(rawData, signature.SigValue.GetValue(), nil)
	if err != nil {
		return err
	}

	// 没有发生任何错误说明验证成功
	return nil
}

// VerifyCPacket
// 验证一个 CPacket 中的签名是否有效
//
// @Description:
// @receiver k
// @param icPacket
// @return error
//
func (k *KeyChain) VerifyCPacket(icPacket *packet.CPacket) error {
	if err := icPacket.FillDataToFields(); err != nil {
		return err
	}
	return k.Verify(&icPacket.MINPacket)
}

// VerifyInterest
// 验证一个 Interest 中的签名是否有效
//
// @Description:
// @receiver k
// @param interest
// @return bool
//
func (k *KeyChain) VerifyInterest(interest *packet.Interest) error {
	if err := interest.FillDataToFields(); err != nil {
		return err
	}
	return k.Verify(&interest.MINPacket)
}

// VerifyData
// 验证一个 Data 中的签名是否有效
//
// @Description:
// @receiver k
// @param mgmt_data
// @return bool
//
func (k *KeyChain) VerifyData(data *packet.Data) error {
	if err := data.FillDataToFields(); err != nil {
		return err
	}
	return k.Verify(&data.MINPacket)
}

// ExportSafeBag
// 将一个网络身份导出为一个 SafeBag 对象
//
// @Description:
// @param identity
// @param password		用于对导出的网络身份整体进行加密
// @return *SafeBag
// @return error
//
func ExportSafeBag(identity *identity.Identity, password string) (*SafeBag, error) {
	res, err := identity.Dump(password)
	if err != nil {
		return nil, err
	}
	safeBag := SafeBag{Value: res}
	return &safeBag, err
}

// ImportSafeBag
// 从一个 SafeBag 中导入网络身份，保存到本地
//
// @Description:
// @receiver k
// @param bag
// @param password
// @param force 		是否强制导入，如果是，则本地存在同名网络身份的情况下会覆盖原有的网络身份
//
func (k *KeyChain) ImportSafeBag(bag *SafeBag, password, path string, force bool) error {
	// 加载一个本地的网络身份
	var newIdentity identity.Identity
	if err := newIdentity.Load(bag.Value, password); err != nil {
		return err
	}

	// 如果当前网络身份不存在，或者存在但是指定了 force = true，则将导入的网络身份进行持久化存储
	if !k.IdentityManager.ExistIdentity(newIdentity.Name) || force {
		if err := k.IdentityManager.SaveIdentity(&newIdentity, force, path, dbFile); err != nil {
			return err
		}
		return nil
	} else {
		// 如果网络身份存在，并且没有指定强制覆盖，则导入失败
		return KeyChainError{msg: fmt.Sprintf(
			"Identity %s is already exists!", newIdentity.Name)}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
///// 错误处理
/////////////////////////////////////////////////////////////////////////////////////////////////////////

type KeyChainError struct {
	msg string
}

func (k KeyChainError) Error() string {
	return fmt.Sprintf("KeyChainError: %s", k.msg)
}

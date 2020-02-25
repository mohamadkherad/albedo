import {generateRandomEncryptionKey} from '../../util/crypto-utils'

const demos = {
    public_key: {
        description: 'Requests user\'s public key. It\'s a simple way of authentication for Stellar-based applications. The response ensures that a user owns the corresponding secret key.',
        params: {
            token: {
                description: 'Verification token generated by the application (should be unique or random).',
                default: generateRandomEncryptionKey()
            }
        }
    },
    basic_info: {
        description: 'Requests user identity (email, avatar, etc). Personal details can be used to set up an email list subscription or personalize the UI.',
        params: {}
    },
    sign_message: {
        description: 'Requests arbitrary message signing. Can be used to implement identity/ownership verification.',
        params: {
            message: {
                description: 'Text message to sign.',
                default: 'Alice doesn\'t trust Bob'
            },
            pubkey: {
                description: 'Specific public key requested by the application.'
            }
        }
    },
    tx: {
        description: 'Requests the signature for a Stellar transaction. Returns signed transaction envelope that can be submitted to the network or used for multi-sig coordination.',
        params: {
            xdr: {
                description: 'XDR-encoded transaction envelope to sign.',
                default: 'AAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAFeACPVIQAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAACGtsbDMyNDIzAAAADgAAAAAAAAAAAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAAL68IAAAAABAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAQAAAACz2XkxfNtDRQygagSaNHaW/fZfk2Z1iIMX92O5O4X1cQAAAAAAAAAAAJiWgAAAAAAAAAACAAAAAURERAAAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAAAAvrwgAAAAACz2XkxfNtDRQygagSaNHaW/fZfk2Z1iIMX92O5O4X1cQAAAAJra2trawAAAAAAAAAAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAAABycOAAAAAAEAAAAAAAAAAAAAAAMAAAAAAAAAAUREAAAAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAAAIFNYSAAAAAwAAAABAAAAAAAAAAAAAAABAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAwAAAAAAAAACREREREQAAAAAAAAAAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAAAAAAAAAAABAAAAAQAAAAAAAAB7AAAAAAAAAAQAAAAAAAAAAVVTRAAAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAAAAJiWgAAAAAEAAAABAAAAAQAAAACz2XkxfNtDRQygagSaNHaW/fZfk2Z1iIMX92O5O4X1cQAAAAUAAAABAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAQAAAAIAAAABAAAAAQAAAAEAAAAEAAAAAQAAAAIAAAABAAAAAgAAAAEAAAACAAAAAQAAAAtleGFtcGxlLmNvbQAAAAABAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAABAAAAAAAAAAGAAAAAUZGAAAAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XF//////////wAAAAEAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAAHAAAAALPZeTF820NFDKBqBJo0dpb99l+TZnWIgxf3Y7k7hfVxAAAAAURERAAAAAAAAAAAAAAAAAcAAAAAs9l5MXzbQ0UMoGoEmjR2lv32X5NmdYiDF/djuTuF9XEAAAABVVNEAAAAAAEAAAAAAAAACAAAAACz2XkxfNtDRQygagSaNHaW/fZfk2Z1iIMX92O5O4X1cQAAAAAAAAAJAAAAAAAAAAoAAAACZGQAAAAAAAEAAAACdnYAAAAAAAAAAAAKAAAAAmtrAAAAAAAAAAAAAAAAAAA='
            },
            pubkey: {
                description: 'Specific public key requested by the application.'
            },
            network: {
                description: 'Stellar account network identifier or private network passphrase.'
            },
            horizon: {
                description: 'The URL of the Horizon server.'
            },
            submit: {
                description: 'If set, the signed transaction will be submitted to the Horizon server instead of returning it to the application.'
            }
        }
    },
    pay: {
        description: 'Requests a payment from a user. Works with any Stellar asset, supports transaction memo.',
        params: {
            amount: {
                description: 'Requested payment amount.',
                default: '1'
            },
            destination: {
                description: 'Payment destination.'
            },
            asset_code: {
                description: 'Asset code (skip for XLM).'
            },
            asset_ssuer: {
                description: 'Asset issuer (skip for XLM).'
            },
            memo: {
                description: 'Transaction memo (required for exchanges and some anchors).'
            },
            memo_type: {
                description: 'Transaction memo type.'
            },
            pubkey: {
                description: 'Specific public key requested by the application.'
            },
            network: {
                description: 'Stellar account network identifier or private network passphrase.'
            },
            horizon: {
                description: 'The URL of the Horizon server.'
            },
            submit: {
                description: 'If set, the signed transaction will be submitted to the Horizon server instead of returning it to the application.'
            }
        }
    },
    trust: {
        description: 'Requests user\'s permission to create a trustline to a given Stellar asset. Gradually simplifies the process of creating trustlines for anchors, ICOs, and airdrops.',
        params: {
            asset_code: {
                description: 'Asset code (skip for XLM).'
            },
            asset_issuer: {
                description: 'Asset issuer (skip for XLM).'
            },
            limit: {
                description: 'Trust limit.'
            },
            pubkey: {
                description: 'Specific public key requested by the application.'
            },
            network: {
                description: 'Stellar account network identifier or private network passphrase.'
            },
            horizon: {
                description: 'The URL of the Horizon server.'
            },
            submit: {
                description: 'If set, the signed transaction will be submitted to the Horizon server instead of returning it to the application.'
            }
        }
    },
    buy_tokens: {
        description: 'Buy token market price',
        params: {
            sell_asset_code: {
                description: 'Asset code of the asset to sell',
                default: 'TEST'
            },
            sell_asset_issuer: {
                description: 'Issuer account of the asset to sell',
                default: 'GCR3MYAUYFVGI4VXPW5TUNAF2U3QWCLSYHE23Q37ITVUUCOLWTCE7PPQ'
            },
            buy_asset_code: {
                description: 'Asset code of the asset to buy',
                default: ''
            },
            buy_asset_issuer: {
                description: 'Issuer account of the asset to buy',
                default: ''
            },
            amount: {
                description: 'Amount',
                default: '1'
            },
            max_price: {
                description: 'Maximum price',
                default: '100'
            },
            network: {
                description: 'Stellar account network identifier or private network passphrase.',
                default: 'testnet'
            },
            horizon: {
                description: 'The URL of the Horizon server.'
            },
            submit: {
                description: 'If set, the signed transaction will be submitted to the Horizon server instead of returning it to the application.'
            }
        }
    },
    implicit_flow: {
        description: 'Requests temporary access token for one or more intents that can be used to execute actions without explicit confirmation from the user.',
        params: {
            intents: {
                description: 'Requested intents for the implicit flow.',
                default: 'tx,pay,trust,sign_message,create_keypair'
            }
        }
    },
    create_keypair: {
        description: 'Requests user\'s permission to create and save new Stellar keypair.',
        params: {
            name: {
                description: 'Keypair name.',
                default: 'new_keypair'
            }
        }
    }
}

export default demos
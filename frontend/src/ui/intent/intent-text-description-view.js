import React from 'react'
import actionContext from '../../state/action-context'
import TxDetailsView from './tx-details-view'
import {formatAddress} from '../../util/formatter'
import {intentInterface} from '@albedo-link/intent'
import {resolveNetworkParams} from '../../util/network-resolver'
import Amount from '../components/amount'
import Address from '../components/account-address'
import AssetName from '../components/asset-name'

function FormattedAmount({amount, params, prefix = ''}) {
    const asset = params[prefix + 'asset_issuer'] ? {
        code: params[prefix + 'asset_code'],
        issuer: params[prefix + 'asset_issuer']
    } : 'XLM'
    return <b><Amount amount={amount} asset={asset}/></b>
}

function IntentErrorView() {
    const {intentErrors, origin} = actionContext
    //TODO: use only unified error objects everywhere in intentErrors to prevent problems with type casting

    let text
    if (intentErrors) {
        text = 'Error: ' + intentErrors.message || intentErrors
        if (!intentErrors.code || intentErrors.code === -1) {
            text += ` It's likely an external application error. Please contact support team of ${origin}.`
        }
    }

    if (text) return <div className="error">{text}</div>
}

export default function IntentTextDescriptionView() {
    const {intent, intentParams, intentErrors, origin} = actionContext
    if (intentErrors) {
        return <>
            <IntentErrorView/>
            <div className="space"/>
        </>
    }
    switch (intent) {
        case 'public_key':
            return <>
                The application requested read-only access to your Stellar account public key.
            </>
        case 'authenticate':
            return <>
                The application requested you to login to {origin}.
            </>
        case 'sign_message':
            return <>
                The application requested permissions to sign a message.
                <div className="space">
                    <span className="label">Message: </span><code
                    className="word-break">{intentParams.message}</code>
                </div>
            </>
        case 'tx':
            const {network} = resolveNetworkParams(intentParams)
            return <>
                The application requested permissions to sign a transaction. Thoroughly examine transaction details
                before confirmation.
                <TxDetailsView xdr={intentParams.xdr} network={network}/>
            </>
        case 'trust':
            return <>
                The application requested a trustline creation to asset <code>{intentParams.asset_code}</code>
                {' '}issued by <code className="word-break">{formatAddress(intentParams.asset_issuer, 16)}</code>.
            </>
        case 'pay':
            return <>
                The application requested a payment <FormattedAmount params={intentParams}
                                                                     amount={intentParams.amount}/>{' '}
                to <b><Address account={intentParams.destination}/></b>.
            </>
        case 'exchange':
            return <>
                The application requested permission to buy {' '}
                <FormattedAmount params={intentParams} prefix="buy_" amount={intentParams.amount}/>{' '}for{' '}
                <AssetName asset={{code: intentParams.sell_asset_code, issuer: intentParams.sell_asset_issuer}}/>{' '}
                at <b>{intentParams.max_price} {intentParams.sell_asset_code || 'XLM'}/{intentParams.buy_asset_code || 'XLM'}</b> or
                lower.
            </>
        /*case 'create_keypair':
            return <>
                The application requested creation of new key pair and access read-only access to its public key.
            </>*/
        case 'implicit_flow':
            return <>
                The application requested a temporary permission to execute the following actions without showing a
                confirmation dialog.
                <ul>
                    {intentParams.intents.map(intent => <li key={intent}>
                        <i className="fa fa-chevron-right"/>
                        <b>{intentInterface[intent].title}</b>
                    </li>)}
                </ul>
                Any granted permission will expire in one hour. Once you close the application, all permissions will
                be automatically revoked.
            </>
    }
    return <span className="error">
        Unknown intent: {intent}.
    </span>
}
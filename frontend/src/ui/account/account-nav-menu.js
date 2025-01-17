import React from 'react'
import {useLocation} from 'react-router'
import cn from 'classnames'
import {useStellarNetwork} from '@stellar-expert/ui-framework'

function NavLink({link, icon, title, current}) {
    return <a href={link} className={cn({current})}>
        <i className={icon}/>
        {title}</a>
}

export default function AccountNavMenu() {
    useLocation()
    useStellarNetwork()

    const links = [
        {link: '/account', icon: 'icon-coins', title: 'Balance'},
        {link: '/wallet/swap', icon: 'icon-switch', title: 'Swap'},
        {link: '/wallet/transfer', icon: 'icon-flash', title: 'Transfer'},
        {link: '/wallet/liquidity-pool', icon: 'icon-liquidity-pool', title: 'Liquidity'},
        {link: '/account-settings', icon: 'icon-settings', title: 'Settings'}
    ]

    return <div className="micro-space navigation">
        {links.filter(link => !!link).map(link => <NavLink key={link.link} {...link}/>)}
    </div>
}
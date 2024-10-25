/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { Request, Response, NextFunction } from 'express'

const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

// Define the redirect allowlist
const redirectAllowlist = new Set([
  'https://github.com/bkimminich/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

// Function to check if the URL is allowed
function isRedirectAllowed(url: string) {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    // If the URL starts with any of the allowed URLs, mark as allowed
    if (url.startsWith(allowedUrl)) {
      allowed = true
      break
    }
  }
  return allowed
}

module.exports = function performRedirect() {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl = query.to
    if (isRedirectAllowed(toUrl as string)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
          toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
          toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
      })
      challengeUtils.solveIf(challenges.redirectChallenge, () => {
        return isUnintendedRedirect(toUrl as string)
      })
      res.redirect(toUrl as string)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect(toUrl: string) {
  let unintended = true
  for (const allowedUrl of redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}

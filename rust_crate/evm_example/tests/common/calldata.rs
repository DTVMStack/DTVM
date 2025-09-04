// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use crate::calculate_selector;
use crate::random_test_address;
use ethabi::{encode, Token};

/// Flexible parameter builder for constructing Vec<Token> in a fluent way
/// Users can chain method calls to build complex parameter lists
#[derive(Debug, Clone, Default)]
pub struct ParamBuilder {
    tokens: Vec<Token>,
}

impl ParamBuilder {
    /// Create a new empty parameter builder
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Add a uint256 parameter
    pub fn uint256(mut self, value: u64) -> Self {
        self.tokens.push(Token::Uint(value.into()));
        self
    }

    /// Add an address parameter
    pub fn address(mut self, address: &[u8; 20]) -> Self {
        self.tokens.push(Token::Address((*address).into()));
        self
    }

    /// Add a bytes parameter
    pub fn bytes(mut self, data: &[u8]) -> Self {
        self.tokens.push(Token::Bytes(data.to_vec()));
        self
    }

    /// Add a fixed bytes parameter (bytes32, etc.)
    pub fn fixed_bytes(mut self, data: &[u8]) -> Self {
        self.tokens.push(Token::FixedBytes(data.to_vec()));
        self
    }

    /// Add a string parameter
    pub fn string(mut self, s: &str) -> Self {
        self.tokens.push(Token::String(s.to_string()));
        self
    }

    /// Add a bool parameter
    pub fn bool(mut self, value: bool) -> Self {
        self.tokens.push(Token::Bool(value));
        self
    }

    /// Add an int256 parameter
    pub fn int256(mut self, value: i64) -> Self {
        self.tokens.push(Token::Int(value.into()));
        self
    }

    /// Add an array of uint256 values
    pub fn uint256_array(mut self, values: &[u64]) -> Self {
        let tokens: Vec<Token> = values.iter().map(|&v| Token::Uint(v.into())).collect();
        self.tokens.push(Token::Array(tokens));
        self
    }

    /// Add an array of addresses
    pub fn address_array(mut self, addresses: &[[u8; 20]]) -> Self {
        let tokens: Vec<Token> = addresses
            .iter()
            .map(|addr| Token::Address((*addr).into()))
            .collect();
        self.tokens.push(Token::Array(tokens));
        self
    }

    /// Add a custom Token directly
    pub fn custom_token(mut self, token: Token) -> Self {
        self.tokens.push(token);
        self
    }

    /// Add multiple custom Tokens
    pub fn custom_tokens(mut self, tokens: Vec<Token>) -> Self {
        self.tokens.extend(tokens);
        self
    }

    /// Build and return the final Vec<Token>
    pub fn build(self) -> Vec<Token> {
        self.tokens
    }

    /// Get the current tokens as a reference (for inspection)
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// Get the number of parameters
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Convenience functions to build common parameter patterns
/// Users can use these for simple cases or use ParamBuilder for complex cases

/// Build no parameters
pub fn params_none() -> Vec<Token> {
    ParamBuilder::new().build()
}

/// Unified function to set call data with selector and tokens
/// This is the main function users should use - pass Vec<Token> directly
pub fn set_call_data_with_params(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    params: Vec<Token>,
) {
    let mut call_data = selector.to_vec();

    if !params.is_empty() {
        call_data.extend_from_slice(&encode(&params));
    }

    context.set_call_data(call_data);
}

## Default Permission

Allows every signing-key operation: probing the platform's capabilities,
generating and reading a key handle, signing, and deleting a key.

#### This default permission set includes the following:

- `allow-capabilities`
- `allow-generate-key`
- `allow-get-key`
- `allow-sign`
- `allow-delete-key`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`sign-keypair:allow-capabilities`

</td>
<td>

Enables the capabilities command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:deny-capabilities`

</td>
<td>

Denies the capabilities command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:allow-delete-key`

</td>
<td>

Enables the delete_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:deny-delete-key`

</td>
<td>

Denies the delete_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:allow-generate-key`

</td>
<td>

Enables the generate_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:deny-generate-key`

</td>
<td>

Denies the generate_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:allow-get-key`

</td>
<td>

Enables the get_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:deny-get-key`

</td>
<td>

Denies the get_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:allow-sign`

</td>
<td>

Enables the sign command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`sign-keypair:deny-sign`

</td>
<td>

Denies the sign command without any pre-configured scope.

</td>
</tr>
</table>

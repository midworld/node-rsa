{
  'targets': [
    {
      'target_name': 'node_rsa',
      'sources': [
        'src/node_rsa.cc'
      ],
	  'include_dirs': [
		'deps/openssl/openssl/include'
	  ],
	  'dependencies': [
 
        'deps/openssl/openssl.gyp:openssl'

      ]
    }
  ]
}
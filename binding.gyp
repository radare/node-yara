{
  'targets': [
    {
      'target_name': 'yara',
      'sources': [
        'src/yara.cc'
      ],
      "include_dirs" : [
        "<!(node -e \"require('nan')\")",
		  './deps/zlib-1.2.11/build/include',
		  './deps/yara-3.5.0/build/include'
      ],
		'libraries': [
         '../deps/zlib-1.2.11/build/lib/libz.a',
         '../deps/yara-3.5.0/build/lib/libyara.a',
		],
      'conditions' : [],
      'actions': [
        {
          'action_name': 'build_libyara',
			 'inputs': [
            'deps/zlib-1.2.11.tar.gz'
			 ],
			 'outputs': [
            'deps/zlib-1.2.11/build'
			 ],
          'action': [
            'make',
            'libyara'
          ]
        }
      ]
    }
  ]
}

{
  'targets': [
    {
      'target_name': 'yara',
      'sources': [
        'src/yara.cc'
      ],
		'cflags_cc!': [
		  '-fno-exceptions',
		  '-fno-rtti'
		],
      "include_dirs" : [
        "<!(node -e \"require('nan')\")",
		  './deps/yara-3.5.0/build/include'
      ],
		'libraries': [
			'-lmagic',
         '../deps/yara-3.5.0/build/lib/libyara.a'
		],
      'conditions' : [],
      'actions': [
        {
          'action_name': 'build_libyara',
			 'inputs': [
            'deps/yara-3.5.0.tar.gz'
			 ],
			 'outputs': [
            'deps/yara-3.5.0/build'
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

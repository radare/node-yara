{
  'targets': [
    {
      'target_name': 'yara',
      'sources': [
        'src/yara.cc'
      ],
      "include_dirs" : [
        "<!(node -e \"require('nan')\")"
      ],
      'conditions' : []
    }
  ]
}

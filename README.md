# pyOpenSprinklerRest

A simple python module for interfacing with the OpenSprinkler REST API with conversion to/from common Python data types.

Getting started:
    os_device = OpenSprinkler(hostname, password, log=log)

    log.info('Get "controller" fields:')
    for prop in Controller.my_get_args.keys():
        log.info('\t%s: %r', prop, getattr(os_device.controller, prop))

    log.info('Get "options" fields:')
    for prop in Options.my_get_args.keys():
        log.info('\t%s: %r', prop, getattr(os_device.options, prop))

    log.info('Setting # expansion boards to 0')
    os_device.options.expander_cnt = 0

    log.info('Setting rain delay for 1 hour')
    os_device.controller.rain_delay = datetime.datetime.now() + datetime.timedelta(hours=4)
    log.info('\tRain delay: %r', os_device.controller.rain_delay)
    log.info('\tRain resume: %r', os_device.controller.rain_resume)

    log.info('Setting rain delay to 0')
    os_device.controller.rain_delay = 0
    log.info('\tRain delay: %r', os_device.controller.rain_delay)
    log.info('\tRain resume: %r',  os_device.controller.rain_resume)

    pprint.pprint(os_device.get_all())

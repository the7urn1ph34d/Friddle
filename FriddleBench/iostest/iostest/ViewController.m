// ViewController.m
#import "ViewController.h"
#import "NativeProcessor.h"

@interface ViewController ()

@property (nonatomic, strong) UITextField       *inputField;
@property (nonatomic, strong) UISegmentedControl *modeControl;
@property (nonatomic, strong) UISwitch          *falsePositiveSwitch;
@property (nonatomic, strong) UILabel           *falsePositiveLabel;
@property (nonatomic, strong) UIButton          *runButton;
@property (nonatomic, strong) UITextView        *outputView;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.whiteColor;


    self.inputField = [[UITextField alloc] initWithFrame:CGRectMake(20, 100, self.view.bounds.size.width - 40, 40)];
    self.inputField.borderStyle = UITextBorderStyleRoundedRect;
    self.inputField.placeholder = @"Enter text";
    [self.view addSubview:self.inputField];


    self.modeControl = [[UISegmentedControl alloc] initWithItems:
        @[@"strcpy",
          @"base64",
          @"aes(self)",
          @"aes(lib)"]];
    self.modeControl.frame = CGRectMake(20, 160, self.view.bounds.size.width - 40, 30);
    self.modeControl.selectedSegmentIndex = 0;
    [self.view addSubview:self.modeControl];

    // False Positive Mode switch
    self.falsePositiveLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 210, 150, 30)];
    self.falsePositiveLabel.text = @"False Positive Mode";
    self.falsePositiveLabel.font = [UIFont systemFontOfSize:16];
    [self.view addSubview:self.falsePositiveLabel];

    self.falsePositiveSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(self.view.bounds.size.width - 80, 210, 51, 31)];
    self.falsePositiveSwitch.on = NO;  // Default to normal mode
    [self.view addSubview:self.falsePositiveSwitch];


    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.frame = CGRectMake((self.view.bounds.size.width - 100)/2, 260, 100, 44);
    [self.runButton setTitle:@"Process" forState:UIControlStateNormal];
    [self.runButton addTarget:self action:@selector(onRunTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runButton];

    self.outputView = [[UITextView alloc] initWithFrame:CGRectMake(20, 320, self.view.bounds.size.width - 40, 200)];
    self.outputView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    self.outputView.layer.borderWidth = 1.0;
    self.outputView.editable = NO;
    [self.view addSubview:self.outputView];
}

- (void)onRunTapped {
    NSString *input = self.inputField.text ?: @"";
    NSInteger mode = self.modeControl.selectedSegmentIndex + 1;
    BOOL falsePositiveMode = self.falsePositiveSwitch.isOn;

    NSString *output = [NativeProcessor process:input mode:mode falsePositiveMode:falsePositiveMode];

    self.outputView.text = output;
}

@end
